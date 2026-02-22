//! LatticeModel integration tests
//!
//! Verifies that deploying a LatticeModel creates the expected Kthena ModelServing,
//! tracing policies, and correct role structure.
//!
//! Run standalone:
//! ```
//! LATTICE_WORKLOAD_KUBECONFIG=/tmp/xxx-e2e-workload-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_model_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use tracing::info;

use super::super::context::{InfraContext, TestSession};
use super::super::helpers::{
    apply_yaml_with_retry, delete_namespace, ensure_namespace, load_fixture_config, run_kubectl,
    setup_regcreds_infrastructure, wait_for_condition, wait_for_resource_phase,
};

const MODEL_NAMESPACE: &str = "serving";
const MODEL_NAME: &str = "llm-serving";

/// Load the model-serving fixture
fn load_model_fixture() -> Result<lattice_common::crd::LatticeModel, String> {
    load_fixture_config("model-serving.yaml")
}

/// Deploy a LatticeModel and verify the controller starts reconciling
async fn test_model_deployment(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Deploying LatticeModel from fixture...");

    ensure_namespace(kubeconfig, MODEL_NAMESPACE).await?;

    let model = load_model_fixture()?;
    let yaml = serde_json::to_string(&model)
        .map_err(|e| format!("Failed to serialize model fixture: {e}"))?;
    apply_yaml_with_retry(kubeconfig, &yaml).await?;

    // Wait for controller to pick up and transition to Loading
    wait_for_resource_phase(
        kubeconfig,
        "latticemodel",
        MODEL_NAMESPACE,
        MODEL_NAME,
        "Loading",
        Duration::from_secs(120),
    )
    .await?;

    info!("[Model] LatticeModel reached Loading phase");
    Ok(())
}

/// Verify ModelServing resource was created with expected role structure
async fn test_model_serving_created(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Verifying ModelServing creation...");

    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "modelservings.workload.serving.volcano.sh",
        MODEL_NAME,
        "-n",
        MODEL_NAMESPACE,
        "-o",
        "json",
    ])
    .await?;

    let ms: serde_json::Value = serde_json::from_str(&output)
        .map_err(|e| format!("Failed to parse ModelServing JSON: {e}"))?;

    // Verify roles Vec has 2 entries (decode, prefill — sorted by BTreeMap)
    let roles = ms["spec"]["template"]["roles"]
        .as_array()
        .ok_or("ModelServing spec.template.roles is not an array")?;

    if roles.len() != 2 {
        return Err(format!("Expected 2 roles, got: {}", roles.len()));
    }

    // Roles are ordered by BTreeMap key: decode first, then prefill
    let decode = roles
        .iter()
        .find(|r| r["name"].as_str() == Some("decode"))
        .ok_or("decode role not found")?;
    let prefill = roles
        .iter()
        .find(|r| r["name"].as_str() == Some("prefill"))
        .ok_or("prefill role not found")?;

    // Verify decode role: replicas=2, workerReplicas=4, both templates present
    if decode["replicas"].as_u64() != Some(2) {
        return Err(format!(
            "decode role: expected replicas=2, got: {}",
            decode["replicas"]
        ));
    }
    if decode["workerReplicas"].as_u64() != Some(4) {
        return Err(format!(
            "decode role: expected workerReplicas=4, got: {}",
            decode["workerReplicas"]
        ));
    }
    if decode["entryTemplate"].is_null() {
        return Err("decode role: entryTemplate is null".to_string());
    }
    if decode["workerTemplate"].is_null() {
        return Err("decode role: workerTemplate is null".to_string());
    }

    // Verify prefill role: replicas=1, no workerReplicas/workerTemplate
    if prefill["replicas"].as_u64() != Some(1) {
        return Err(format!(
            "prefill role: expected replicas=1, got: {}",
            prefill["replicas"]
        ));
    }
    if !prefill["workerReplicas"].is_null() {
        return Err(format!(
            "prefill role: expected no workerReplicas, got: {}",
            prefill["workerReplicas"]
        ));
    }
    if !prefill["workerTemplate"].is_null() {
        return Err(format!(
            "prefill role: expected no workerTemplate, got: {}",
            prefill["workerTemplate"]
        ));
    }

    // Verify gangPolicy.minRoleReplicas
    let gang = &ms["spec"]["template"]["gangPolicy"];
    if gang.is_null() {
        return Err("gangPolicy is null".to_string());
    }
    let min_replicas = &gang["minRoleReplicas"];
    if min_replicas["decode"].as_u64() != Some(2) {
        return Err(format!(
            "gangPolicy: expected decode minRoleReplicas=2, got: {}",
            min_replicas["decode"]
        ));
    }
    if min_replicas["prefill"].as_u64() != Some(1) {
        return Err(format!(
            "gangPolicy: expected prefill minRoleReplicas=1, got: {}",
            min_replicas["prefill"]
        ));
    }

    // Verify schedulerName
    let scheduler = ms["spec"]["schedulerName"]
        .as_str()
        .unwrap_or_default();
    if scheduler != "volcano" {
        return Err(format!(
            "Expected schedulerName 'volcano', got: '{scheduler}'"
        ));
    }

    // Verify restartGracePeriodSeconds
    if ms["spec"]["template"]["restartGracePeriodSeconds"].as_i64() != Some(30) {
        return Err(format!(
            "Expected restartGracePeriodSeconds=30, got: {}",
            ms["spec"]["template"]["restartGracePeriodSeconds"]
        ));
    }

    // Verify ownerReferences
    let owner_kind = ms["metadata"]["ownerReferences"][0]["kind"]
        .as_str()
        .unwrap_or_default();
    if owner_kind != "LatticeModel" {
        return Err(format!(
            "Expected ownerReference kind 'LatticeModel', got: '{owner_kind}'"
        ));
    }

    info!("[Model] ModelServing verified: 2 roles (decode+prefill), gang policy, correct owner reference");
    Ok(())
}

/// Verify TracingPolicyNamespaced resources were created for each role
async fn test_tracing_policies_created(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Verifying TracingPolicyNamespaced resources...");

    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "tracingpolicynamespaced",
        "-n",
        MODEL_NAMESPACE,
        "-o",
        "jsonpath={.items[*].metadata.name}",
    ])
    .await?;

    let policies: Vec<&str> = output.trim().split_whitespace().collect();
    info!("[Model] Found tracing policies: {:?}", policies);

    // Each role's entry should have a tracing policy, plus workers for decode
    let expected = [
        format!("allow-binaries-{}-prefill", MODEL_NAME),
        format!("allow-binaries-{}-decode", MODEL_NAME),
        format!("allow-binaries-{}-decode-worker", MODEL_NAME),
    ];

    for expected_name in &expected {
        if !policies.contains(&expected_name.as_str()) {
            return Err(format!(
                "Expected tracing policy '{}', found: {:?}",
                expected_name, policies
            ));
        }
    }

    info!("[Model] TracingPolicyNamespaced resources verified (prefill + decode entry + decode worker)");
    Ok(())
}

/// Wait for the model to reach Serving phase (Kthena processes ModelServing)
async fn test_model_serving_phase(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Waiting for Serving phase (Kthena processing)...");

    wait_for_resource_phase(
        kubeconfig,
        "latticemodel",
        MODEL_NAMESPACE,
        MODEL_NAME,
        "Serving",
        Duration::from_secs(300),
    )
    .await?;

    // Verify observedGeneration was set
    let observed = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticemodel",
        MODEL_NAME,
        "-n",
        MODEL_NAMESPACE,
        "-o",
        "jsonpath={.status.observedGeneration}",
    ])
    .await?;

    let gen = observed.trim();
    if gen.is_empty() || gen == "0" {
        return Err(format!("Expected observedGeneration > 0, got: '{gen}'"));
    }

    info!("[Model] Model reached Serving phase (observedGeneration={gen})");
    Ok(())
}

/// Verify ModelServer and ModelRoute resources were created for routing
async fn test_model_routing_created(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Verifying routing resources (ModelServer + ModelRoute)...");

    // Verify ModelServer
    let ms_output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "modelservers.networking.serving.volcano.sh",
        MODEL_NAME,
        "-n",
        MODEL_NAMESPACE,
        "-o",
        "json",
    ])
    .await?;

    let ms: serde_json::Value = serde_json::from_str(&ms_output)
        .map_err(|e| format!("Failed to parse ModelServer JSON: {e}"))?;

    // Verify workloadSelector matches the model name
    let match_labels = &ms["spec"]["workloadSelector"]["matchLabels"];
    let selector_value = match_labels["modelserving.volcano.sh/name"]
        .as_str()
        .unwrap_or_default();
    if selector_value != MODEL_NAME {
        return Err(format!(
            "ModelServer workloadSelector should match model name '{}', got: '{}'",
            MODEL_NAME, selector_value
        ));
    }

    // Verify inference engine
    let engine = ms["spec"]["inferenceEngine"]
        .as_str()
        .unwrap_or_default();
    if engine != "vLLM" {
        return Err(format!(
            "ModelServer inferenceEngine should be 'vLLM', got: '{engine}'"
        ));
    }

    // Verify model name
    let model_field = ms["spec"]["model"]
        .as_str()
        .unwrap_or_default();
    if model_field != "deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B" {
        return Err(format!(
            "ModelServer model should be 'deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B', got: '{model_field}'"
        ));
    }

    // Verify workload port
    if ms["spec"]["workloadPort"]["port"].as_u64() != Some(8000) {
        return Err(format!(
            "ModelServer workloadPort should be 8000, got: {}",
            ms["spec"]["workloadPort"]["port"]
        ));
    }

    // Verify PD disaggregation (fixture has kvConnector + prefill/decode roles)
    let pd_group = &ms["spec"]["workloadSelector"]["pdGroup"];
    if pd_group.is_null() {
        return Err("ModelServer pdGroup should be set (fixture has kvConnector + prefill/decode roles)".to_string());
    }
    let group_key = pd_group["groupKey"].as_str().unwrap_or_default();
    if group_key != "modelserving.volcano.sh/group-name" {
        return Err(format!(
            "pdGroup groupKey should be 'modelserving.volcano.sh/group-name', got: '{group_key}'"
        ));
    }
    let prefill_role_label = pd_group["prefillLabels"]["modelserving.volcano.sh/role"]
        .as_str()
        .unwrap_or_default();
    if prefill_role_label != "prefill" {
        return Err(format!(
            "pdGroup prefillLabels role should be 'prefill', got: '{prefill_role_label}'"
        ));
    }
    let decode_role_label = pd_group["decodeLabels"]["modelserving.volcano.sh/role"]
        .as_str()
        .unwrap_or_default();
    if decode_role_label != "decode" {
        return Err(format!(
            "pdGroup decodeLabels role should be 'decode', got: '{decode_role_label}'"
        ));
    }

    // Verify kvConnector
    let kv_type = ms["spec"]["kvConnector"]["type"]
        .as_str()
        .unwrap_or_default();
    if kv_type != "nixl" {
        return Err(format!(
            "ModelServer kvConnector type should be 'nixl', got: '{kv_type}'"
        ));
    }

    // Verify trafficPolicy retry
    if ms["spec"]["trafficPolicy"]["retry"]["attempts"].as_u64() != Some(3) {
        return Err(format!(
            "ModelServer trafficPolicy retry attempts should be 3, got: {}",
            ms["spec"]["trafficPolicy"]["retry"]["attempts"]
        ));
    }

    // Verify ownerReferences on ModelServer
    let ms_owner_kind = ms["metadata"]["ownerReferences"][0]["kind"]
        .as_str()
        .unwrap_or_default();
    if ms_owner_kind != "LatticeModel" {
        return Err(format!(
            "ModelServer ownerReference kind should be 'LatticeModel', got: '{ms_owner_kind}'"
        ));
    }

    info!("[Model] ModelServer verified: model, workload selector, PD group, kvConnector, trafficPolicy, owner ref");

    // Verify ModelRoute
    let route_name = format!("{}-default", MODEL_NAME);
    let mr_output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "modelroutes.networking.serving.volcano.sh",
        &route_name,
        "-n",
        MODEL_NAMESPACE,
        "-o",
        "json",
    ])
    .await?;

    let mr: serde_json::Value = serde_json::from_str(&mr_output)
        .map_err(|e| format!("Failed to parse ModelRoute JSON: {e}"))?;

    // Verify modelName defaults to routing.model
    let model_name = mr["spec"]["modelName"]
        .as_str()
        .unwrap_or_default();
    if model_name != "deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B" {
        return Err(format!(
            "ModelRoute modelName should be 'deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B', got: '{model_name}'"
        ));
    }

    // Verify target model server name defaults to model name
    let target = &mr["spec"]["rules"][0]["targetModels"][0];
    let target_name = target["modelServerName"]
        .as_str()
        .unwrap_or_default();
    if target_name != MODEL_NAME {
        return Err(format!(
            "ModelRoute targetModels should reference '{}', got: '{}'",
            MODEL_NAME, target_name
        ));
    }

    // Verify weight on target model
    if target["weight"].as_u64() != Some(100) {
        return Err(format!(
            "ModelRoute target weight should be 100, got: {}",
            target["weight"]
        ));
    }

    // Verify ownerReferences on ModelRoute
    let mr_owner_kind = mr["metadata"]["ownerReferences"][0]["kind"]
        .as_str()
        .unwrap_or_default();
    if mr_owner_kind != "LatticeModel" {
        return Err(format!(
            "ModelRoute ownerReference kind should be 'LatticeModel', got: '{mr_owner_kind}'"
        ));
    }

    info!("[Model] ModelRoute verified: modelName, target, weight, owner ref");
    Ok(())
}

/// Verify AutoscalingPolicy and AutoscalingPolicyBinding were created for the decode role
async fn test_model_autoscaling_created(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Verifying autoscaling resources (AutoscalingPolicy + AutoscalingPolicyBinding)...");

    let policy_name = format!("{}-decode-scaling", MODEL_NAME);

    // Verify AutoscalingPolicy
    let ap_output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "autoscalingpolicies.workload.serving.volcano.sh",
        &policy_name,
        "-n",
        MODEL_NAMESPACE,
        "-o",
        "json",
    ])
    .await?;

    let ap: serde_json::Value = serde_json::from_str(&ap_output)
        .map_err(|e| format!("Failed to parse AutoscalingPolicy JSON: {e}"))?;

    // Verify apiVersion and kind
    let api_version = ap["apiVersion"].as_str().unwrap_or_default();
    if api_version != "workload.serving.volcano.sh/v1alpha1" {
        return Err(format!(
            "AutoscalingPolicy apiVersion should be 'workload.serving.volcano.sh/v1alpha1', got: '{api_version}'"
        ));
    }

    // Verify metrics
    let metrics = ap["spec"]["metrics"]
        .as_array()
        .ok_or("AutoscalingPolicy spec.metrics is not an array")?;
    if metrics.len() != 1 {
        return Err(format!("Expected 1 metric, got: {}", metrics.len()));
    }
    let metric_name = metrics[0]["metricName"].as_str().unwrap_or_default();
    if metric_name != "gpu_kv_cache_usage" {
        return Err(format!(
            "Expected metric 'gpu_kv_cache_usage', got: '{metric_name}'"
        ));
    }
    let target_value = metrics[0]["targetValue"].as_f64().unwrap_or(0.0);
    if (target_value - 0.8).abs() > 0.001 {
        return Err(format!(
            "Expected target value 0.8, got: {target_value}"
        ));
    }

    // Verify tolerancePercent
    if ap["spec"]["tolerancePercent"].as_u64() != Some(10) {
        return Err(format!(
            "Expected tolerancePercent=10, got: {}",
            ap["spec"]["tolerancePercent"]
        ));
    }

    // Verify behavior
    let behavior = &ap["spec"]["behavior"];
    if behavior.is_null() {
        return Err("AutoscalingPolicy behavior should be set".to_string());
    }

    // Verify scale-up panic policy
    let panic = &behavior["scaleUp"]["panicPolicy"];
    if panic["panicThresholdPercent"].as_u64() != Some(200) {
        return Err(format!(
            "Expected panicThresholdPercent=200, got: {}",
            panic["panicThresholdPercent"]
        ));
    }
    if panic["panicModeHold"].as_str() != Some("5m") {
        return Err(format!(
            "Expected panicModeHold='5m', got: {}",
            panic["panicModeHold"]
        ));
    }

    // Verify scale-up stable policy
    let stable = &behavior["scaleUp"]["stablePolicy"];
    if stable["stabilizationWindow"].as_str() != Some("1m") {
        return Err(format!(
            "Expected scaleUp stabilizationWindow='1m', got: {}",
            stable["stabilizationWindow"]
        ));
    }
    if stable["period"].as_str() != Some("30s") {
        return Err(format!(
            "Expected scaleUp period='30s', got: {}",
            stable["period"]
        ));
    }

    // Verify scale-down behavior
    let scale_down = &behavior["scaleDown"];
    if scale_down["stabilizationWindow"].as_str() != Some("5m") {
        return Err(format!(
            "Expected scaleDown stabilizationWindow='5m', got: {}",
            scale_down["stabilizationWindow"]
        ));
    }
    if scale_down["period"].as_str() != Some("1m") {
        return Err(format!(
            "Expected scaleDown period='1m', got: {}",
            scale_down["period"]
        ));
    }

    // Verify ownerReferences
    let ap_owner = ap["metadata"]["ownerReferences"][0]["kind"]
        .as_str()
        .unwrap_or_default();
    if ap_owner != "LatticeModel" {
        return Err(format!(
            "AutoscalingPolicy ownerReference kind should be 'LatticeModel', got: '{ap_owner}'"
        ));
    }

    info!("[Model] AutoscalingPolicy verified: metrics, tolerance, behavior (panic + stable + scale-down), owner ref");

    // Verify AutoscalingPolicyBinding
    let apb_output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "autoscalingpolicybindings.workload.serving.volcano.sh",
        &policy_name,
        "-n",
        MODEL_NAMESPACE,
        "-o",
        "json",
    ])
    .await?;

    let apb: serde_json::Value = serde_json::from_str(&apb_output)
        .map_err(|e| format!("Failed to parse AutoscalingPolicyBinding JSON: {e}"))?;

    // Verify policyRef
    let policy_ref_name = apb["spec"]["policyRef"]["name"]
        .as_str()
        .unwrap_or_default();
    if policy_ref_name != policy_name {
        return Err(format!(
            "Binding policyRef.name should be '{}', got: '{policy_ref_name}'",
            policy_name
        ));
    }

    // Verify homogeneousTarget
    let target = &apb["spec"]["homogeneousTarget"];

    // Verify targetRef → ModelServing
    let target_kind = target["target"]["targetRef"]["kind"]
        .as_str()
        .unwrap_or_default();
    if target_kind != "ModelServing" {
        return Err(format!(
            "Binding targetRef kind should be 'ModelServing', got: '{target_kind}'"
        ));
    }
    let target_name = target["target"]["targetRef"]["name"]
        .as_str()
        .unwrap_or_default();
    if target_name != MODEL_NAME {
        return Err(format!(
            "Binding targetRef name should be '{}', got: '{target_name}'",
            MODEL_NAME
        ));
    }

    // Verify subTarget → Role/decode
    let sub_kind = target["target"]["subTarget"]["kind"]
        .as_str()
        .unwrap_or_default();
    if sub_kind != "Role" {
        return Err(format!(
            "Binding subTarget kind should be 'Role', got: '{sub_kind}'"
        ));
    }
    let sub_name = target["target"]["subTarget"]["name"]
        .as_str()
        .unwrap_or_default();
    if sub_name != "decode" {
        return Err(format!(
            "Binding subTarget name should be 'decode', got: '{sub_name}'"
        ));
    }

    // Verify min/max replicas
    if target["minReplicas"].as_u64() != Some(2) {
        return Err(format!(
            "Binding minReplicas should be 2, got: {}",
            target["minReplicas"]
        ));
    }
    if target["maxReplicas"].as_u64() != Some(8) {
        return Err(format!(
            "Binding maxReplicas should be 8, got: {}",
            target["maxReplicas"]
        ));
    }

    // Verify ownerReferences on binding
    let apb_owner = apb["metadata"]["ownerReferences"][0]["kind"]
        .as_str()
        .unwrap_or_default();
    if apb_owner != "LatticeModel" {
        return Err(format!(
            "AutoscalingPolicyBinding ownerReference kind should be 'LatticeModel', got: '{apb_owner}'"
        ));
    }

    info!("[Model] AutoscalingPolicyBinding verified: policyRef, target (ModelServing/{}, Role/decode), min=2, max=8, owner ref", MODEL_NAME);

    // Verify prefill role does NOT have autoscaling resources
    let prefill_policy = format!("{}-prefill-scaling", MODEL_NAME);
    let prefill_check = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "autoscalingpolicies.workload.serving.volcano.sh",
        &prefill_policy,
        "-n",
        MODEL_NAMESPACE,
        "-o",
        "name",
    ])
    .await;

    if prefill_check.is_ok() {
        return Err(format!(
            "Prefill role should NOT have an AutoscalingPolicy ('{prefill_policy}' should not exist)"
        ));
    }

    info!("[Model] Verified: prefill role has no autoscaling resources (as expected)");
    info!("[Model] All autoscaling resources verified!");
    Ok(())
}

/// Verify model download PVC was created
async fn test_model_download_pvc(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Verifying model download PVC...");

    let pvc_name = format!("vol-{}-model-cache", MODEL_NAME);
    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "pvc",
        &pvc_name,
        "-n",
        MODEL_NAMESPACE,
        "-o",
        "json",
    ])
    .await?;

    let pvc: serde_json::Value = serde_json::from_str(&output)
        .map_err(|e| format!("Failed to parse PVC JSON: {e}"))?;

    // Verify size
    let storage = pvc["spec"]["resources"]["requests"]["storage"]
        .as_str()
        .unwrap_or_default();
    if storage != "1Gi" {
        return Err(format!("PVC storage should be '1Gi', got: '{storage}'"));
    }

    // Verify access mode
    let access_modes = pvc["spec"]["accessModes"]
        .as_array()
        .ok_or("PVC accessModes is not an array")?;
    if !access_modes.iter().any(|m| m == "ReadWriteOnce") {
        return Err(format!(
            "PVC should have ReadWriteOnce access mode, got: {:?}",
            access_modes
        ));
    }

    // Verify owner reference
    let owner_kind = pvc["metadata"]["ownerReferences"][0]["kind"]
        .as_str()
        .unwrap_or_default();
    if owner_kind != "LatticeModel" {
        return Err(format!(
            "PVC ownerReference kind should be 'LatticeModel', got: '{owner_kind}'"
        ));
    }

    info!("[Model] Model download PVC verified: 1Gi, ReadWriteOnce, correct owner ref");
    Ok(())
}

/// Verify model download LatticeJob was created
async fn test_model_download_job(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Verifying model download LatticeJob...");

    let job_name = format!("{}-download", MODEL_NAME);
    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticejob",
        &job_name,
        "-n",
        MODEL_NAMESPACE,
        "-o",
        "json",
    ])
    .await?;

    let job: serde_json::Value = serde_json::from_str(&output)
        .map_err(|e| format!("Failed to parse LatticeJob JSON: {e}"))?;

    // Verify maxRetry
    if job["spec"]["maxRetry"].as_u64() != Some(3) {
        return Err(format!(
            "LatticeJob maxRetry should be 3, got: {}",
            job["spec"]["maxRetry"]
        ));
    }

    // Verify single "download" task
    let tasks = &job["spec"]["tasks"];
    if tasks["download"].is_null() {
        return Err("LatticeJob should have a 'download' task".to_string());
    }

    let task = &tasks["download"];

    // Verify container image (HuggingFace uses python:3.11-slim)
    let image = task["workload"]["containers"]["download"]["image"]
        .as_str()
        .unwrap_or_default();
    if image != "python:3.11-slim" {
        return Err(format!(
            "Download container image should be 'python:3.11-slim', got: '{image}'"
        ));
    }

    // Verify command references the model
    let cmd = task["workload"]["containers"]["download"]["command"][2]
        .as_str()
        .unwrap_or_default();
    if !cmd.contains("huggingface-cli download hf-internal-testing/tiny-random-LlamaForCausalLM") {
        return Err(format!(
            "Download command should reference 'hf-internal-testing/tiny-random-LlamaForCausalLM', got: '{cmd}'"
        ));
    }

    // Verify volume resource (reference to PVC)
    let vol_resource = &task["workload"]["resources"]["model-cache"];
    if vol_resource["type"].as_str() != Some("volume") {
        return Err(format!(
            "model-cache resource type should be 'volume', got: {}",
            vol_resource["type"]
        ));
    }

    // Verify entity egress resource
    let egress_resource = &task["workload"]["resources"]["internet"];
    if egress_resource["type"].as_str() != Some("external-service") {
        return Err(format!(
            "internet resource type should be 'external-service', got: {}",
            egress_resource["type"]
        ));
    }
    if egress_resource["id"].as_str() != Some("entity:world:443") {
        return Err(format!(
            "internet resource id should be 'entity:world:443', got: {}",
            egress_resource["id"]
        ));
    }

    info!("[Model] LatticeJob verified: python:3.11-slim, huggingface-cli download, volume + egress resources");
    Ok(())
}

/// Verify download mesh member has entity egress
async fn test_model_download_mesh_member(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Verifying download mesh member (entity egress)...");

    // LatticeJob task "download" with job name "llm-serving-download" produces
    // mesh member named "llm-serving-download-download"
    let mm_name = format!("{}-download-download", MODEL_NAME);
    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticemeshmembers",
        &mm_name,
        "-n",
        MODEL_NAMESPACE,
        "-o",
        "json",
    ])
    .await?;

    let mm: serde_json::Value = serde_json::from_str(&output)
        .map_err(|e| format!("Failed to parse download MeshMember JSON: {e}"))?;

    // Should have egress rules
    let egress = mm["spec"]["egress"]
        .as_array()
        .ok_or("Download mesh member should have egress rules")?;
    if egress.is_empty() {
        return Err("Download mesh member egress should not be empty".to_string());
    }

    // Verify entity egress target
    let has_world_egress = egress.iter().any(|rule| {
        rule["target"]["entity"].as_str() == Some("world")
    });
    if !has_world_egress {
        return Err(format!(
            "Download mesh member should have Entity(\"world\") egress, got: {:?}",
            egress
        ));
    }

    // Should be egress-only (no ports)
    let ports = mm["spec"]["ports"]
        .as_array()
        .map(|p| p.len())
        .unwrap_or(0);
    if ports != 0 {
        return Err(format!(
            "Download mesh member should have no ports (egress-only), got: {}",
            ports
        ));
    }

    info!("[Model] Download mesh member verified: entity egress to 'world', egress-only");
    Ok(())
}

/// Verify ModelServing pod templates have scheduling gates and model volume
async fn test_model_serving_has_download_injection(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Verifying scheduling gates and model volume on ModelServing...");

    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "modelservings.workload.serving.volcano.sh",
        MODEL_NAME,
        "-n",
        MODEL_NAMESPACE,
        "-o",
        "json",
    ])
    .await?;

    let ms: serde_json::Value = serde_json::from_str(&output)
        .map_err(|e| format!("Failed to parse ModelServing JSON: {e}"))?;

    let roles = ms["spec"]["template"]["roles"]
        .as_array()
        .ok_or("roles is not an array")?;

    for role in roles {
        let role_name = role["name"].as_str().unwrap_or("unknown");

        // Check scheduling gate on entry template
        let gates = role["entryTemplate"]["spec"]["schedulingGates"]
            .as_array()
            .ok_or(format!(
                "role '{}' entryTemplate missing schedulingGates",
                role_name
            ))?;
        let has_download_gate = gates
            .iter()
            .any(|g| g["name"] == "lattice.dev/model-download");
        if !has_download_gate {
            return Err(format!(
                "role '{}' entryTemplate missing lattice.dev/model-download gate",
                role_name
            ));
        }

        // Check model-cache volume on entry template
        let empty = vec![];
        let volumes = role["entryTemplate"]["spec"]["volumes"]
            .as_array()
            .unwrap_or(&empty);
        let has_model_volume = volumes.iter().any(|v| v["name"] == "model-cache");
        if !has_model_volume {
            return Err(format!(
                "role '{}' entryTemplate missing model-cache volume",
                role_name
            ));
        }

        // Check volumeMount on entry template containers
        let containers = role["entryTemplate"]["spec"]["containers"]
            .as_array()
            .ok_or(format!(
                "role '{}' entryTemplate missing containers",
                role_name
            ))?;
        for container in containers {
            let c_name = container["name"].as_str().unwrap_or("unknown");
            let mounts = container["volumeMounts"]
                .as_array()
                .unwrap_or(&empty);
            let has_mount = mounts.iter().any(|m| {
                m["name"] == "model-cache"
                    && m["mountPath"] == "/models"
                    && m["readOnly"] == true
            });
            if !has_mount {
                return Err(format!(
                    "role '{}' container '{}' missing model-cache volumeMount",
                    role_name, c_name
                ));
            }
        }

        // Check worker template if present (decode role has workers)
        if !role["workerTemplate"].is_null() {
            let worker_gates = role["workerTemplate"]["spec"]["schedulingGates"]
                .as_array()
                .ok_or(format!(
                    "role '{}' workerTemplate missing schedulingGates",
                    role_name
                ))?;
            let worker_has_gate = worker_gates
                .iter()
                .any(|g| g["name"] == "lattice.dev/model-download");
            if !worker_has_gate {
                return Err(format!(
                    "role '{}' workerTemplate missing lattice.dev/model-download gate",
                    role_name
                ));
            }
        }

        info!(
            "[Model] Role '{}': scheduling gate + model volume verified",
            role_name
        );
    }

    info!("[Model] All role templates have scheduling gates and model volume");
    Ok(())
}

/// Verify LatticeMeshMember resources include Kthena router and autoscaler as allowed callers
async fn test_model_mesh_members(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Verifying mesh members allow Kthena router and autoscaler traffic...");

    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticemeshmembers",
        "-n",
        MODEL_NAMESPACE,
        "-o",
        "json",
    ])
    .await?;

    let members: serde_json::Value = serde_json::from_str(&output)
        .map_err(|e| format!("Failed to parse LatticeMeshMember list: {e}"))?;

    let items = members["items"]
        .as_array()
        .ok_or("LatticeMeshMember items is not an array")?;

    if items.is_empty() {
        return Err("No LatticeMeshMember resources found".to_string());
    }

    // Filter out download mesh member (egress-only, no ports/callers) —
    // it's verified separately in test_model_download_mesh_member.
    let download_mm_name = format!("{}-download-download", MODEL_NAME);
    let role_items: Vec<_> = items
        .iter()
        .filter(|item| item["metadata"]["name"].as_str() != Some(&download_mm_name))
        .collect();

    if role_items.is_empty() {
        return Err("No role LatticeMeshMember resources found (only download)".to_string());
    }

    for item in &role_items {
        let mm_name = item["metadata"]["name"]
            .as_str()
            .unwrap_or("unknown");

        // Check that the Kthena router is in allowed_callers
        let empty_arr = vec![];
        let callers = item["spec"]["allowedCallers"]
            .as_array()
            .unwrap_or(&empty_arr);
        let has_router = callers.iter().any(|c| {
            c["name"].as_str() == Some("kthena-router")
                && c["namespace"].as_str() == Some("kthena-system")
        });
        if !has_router {
            return Err(format!(
                "LatticeMeshMember '{}' is missing Kthena router in allowedCallers",
                mm_name
            ));
        }

        // Check inference port is present
        let empty_ports = vec![];
        let ports = item["spec"]["ports"]
            .as_array()
            .unwrap_or(&empty_ports);
        let has_inference_port = ports.iter().any(|p| p["port"].as_u64() == Some(8000));
        if !has_inference_port {
            return Err(format!(
                "LatticeMeshMember '{}' is missing inference port 8000",
                mm_name
            ));
        }

        // Verify allowPeerTraffic is enabled (PD disaggregation: kvConnector + prefill/decode)
        let peer_traffic = item["spec"]["allowPeerTraffic"]
            .as_bool()
            .unwrap_or(false);
        if !peer_traffic {
            return Err(format!(
                "LatticeMeshMember '{}' should have allowPeerTraffic=true for PD disaggregation",
                mm_name
            ));
        }

        info!(
            "[Model] MeshMember '{}': Kthena router allowed, inference port present, peer traffic enabled",
            mm_name
        );
    }

    // Verify decode role mesh members have the autoscaler as an allowed caller
    // (decode has autoscaling configured with entry_workload service port "metrics"=9090)
    let decode_entry_name = format!("{}-decode", MODEL_NAME);
    let decode_mm = items
        .iter()
        .find(|item| item["metadata"]["name"].as_str() == Some(&decode_entry_name));
    if let Some(mm) = decode_mm {
        let empty_arr = vec![];
        let callers = mm["spec"]["allowedCallers"]
            .as_array()
            .unwrap_or(&empty_arr);
        let has_autoscaler = callers.iter().any(|c| {
            c["name"].as_str() == Some("kthena-autoscaler")
                && c["namespace"].as_str() == Some("kthena-system")
        });
        if !has_autoscaler {
            return Err(format!(
                "LatticeMeshMember '{}' is missing Kthena autoscaler in allowedCallers",
                decode_entry_name
            ));
        }

        let empty_ports = vec![];
        let ports = mm["spec"]["ports"]
            .as_array()
            .unwrap_or(&empty_ports);
        let has_metrics_port = ports.iter().any(|p| p["port"].as_u64() == Some(9090));
        if !has_metrics_port {
            return Err(format!(
                "LatticeMeshMember '{}' is missing metrics port 9090 (from entry_workload service ports)",
                decode_entry_name
            ));
        }

        info!(
            "[Model] MeshMember '{}': Kthena autoscaler allowed + metrics port 9090 present",
            decode_entry_name
        );
    } else {
        return Err(format!(
            "LatticeMeshMember '{}' not found for autoscaler verification",
            decode_entry_name
        ));
    }

    info!("[Model] All mesh members correctly configured for Kthena routing, autoscaling, and PD disaggregation");
    Ok(())
}

/// Verify download LatticeJob completes and scheduling gates are removed
async fn test_download_lifecycle(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Waiting for download LatticeJob to complete...");

    let job_name = format!("{}-download", MODEL_NAME);
    wait_for_resource_phase(
        kubeconfig,
        "latticejob",
        MODEL_NAMESPACE,
        &job_name,
        "Succeeded",
        Duration::from_secs(300),
    )
    .await?;

    info!("[Model] Download LatticeJob completed, verifying scheduling gates are removed...");

    // After Job completes, the controller should remove scheduling gates from pods
    let label_selector = format!("modelserving.volcano.sh/name={}", MODEL_NAME);
    let kc = kubeconfig.to_string();
    let ls = label_selector.clone();

    wait_for_condition(
        "scheduling gates to be removed from model pods",
        Duration::from_secs(120),
        Duration::from_secs(5),
        || {
            let kc = kc.clone();
            let ls = ls.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "pods",
                    "-n",
                    MODEL_NAMESPACE,
                    "-l",
                    &ls,
                    "-o",
                    "jsonpath={.items[*].spec.schedulingGates}",
                ])
                .await;

                match output {
                    Ok(gates) => {
                        let gates = gates.trim();
                        // Empty or no gates means they've been removed
                        let removed = gates.is_empty()
                            || !gates.contains("lattice.dev/model-download");
                        info!(
                            "[Model] Scheduling gates: {}",
                            if gates.is_empty() { "(none)" } else { gates }
                        );
                        Ok(removed)
                    }
                    Err(e) => {
                        info!("[Model] Could not check scheduling gates: {}", e);
                        Ok(false)
                    }
                }
            }
        },
    )
    .await?;

    info!("[Model] Download lifecycle verified: LatticeJob completed + scheduling gates removed");
    Ok(())
}

/// Run all model integration tests
pub async fn run_model_tests(ctx: &InfraContext) -> Result<(), String> {
    let kubeconfig = ctx.require_workload()?;
    info!("[Model] Running LatticeModel integration tests on {kubeconfig}");

    // GHCR registry credentials + Cedar policies (includes AppArmor override)
    setup_regcreds_infrastructure(kubeconfig).await?;

    // Deploy the model
    test_model_deployment(kubeconfig).await?;

    // Verify download resources were created (modelSource configured)
    test_model_download_pvc(kubeconfig).await?;
    test_model_download_job(kubeconfig).await?;
    test_model_download_mesh_member(kubeconfig).await?;
    test_model_serving_has_download_injection(kubeconfig).await?;

    // Verify resources were created
    test_model_serving_created(kubeconfig).await?;
    test_tracing_policies_created(kubeconfig).await?;
    test_model_routing_created(kubeconfig).await?;
    test_model_autoscaling_created(kubeconfig).await?;
    test_model_mesh_members(kubeconfig).await?;

    // Wait for download lifecycle: LatticeJob completes + scheduling gates removed
    test_download_lifecycle(kubeconfig).await?;

    // Wait for full lifecycle (Kthena processing — now reachable after gates removed)
    test_model_serving_phase(kubeconfig).await?;

    // Cleanup
    delete_namespace(kubeconfig, MODEL_NAMESPACE).await;

    info!("[Model] All LatticeModel integration tests passed!");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_model_standalone() {
    let session = TestSession::from_env(
        "Set LATTICE_WORKLOAD_KUBECONFIG to run standalone model tests",
    )
    .await
    .expect("Failed to create test session");

    if let Err(e) = run_model_tests(&session.ctx).await {
        panic!("Model tests failed: {e}");
    }
}
