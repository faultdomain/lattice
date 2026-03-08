//! LatticeModel integration tests
//!
//! Verifies that deploying a LatticeModel creates the expected Kthena ModelServing,
//! tracing policies, and correct role structure.
//!
//! Run standalone:
//! ```
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_model_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::collections::BTreeMap;
use std::time::Duration;

use tracing::info;

use lattice_common::crd::{ContainerSpec, ResourceQuantity, ResourceRequirements, SecurityContext};

use super::super::helpers::{
    apply_yaml, build_busybox_service, delete_namespace, deploy_and_wait_for_phase,
    ensure_fresh_namespace, load_fixture_config, resolve_model_serving_name, run_kubectl,
    setup_regcreds_infrastructure, wait_for_condition, wait_for_resource_phase, TestHarness,
    with_diagnostics, DiagnosticContext, CURL_IMAGE, CYCLE_END_MARKER, CYCLE_START_MARKER,
    DEFAULT_TIMEOUT,
};
use super::super::mesh_helpers::parse_traffic_result;

const MODEL_NAMESPACE: &str = "serving";
const MODEL_NAME: &str = "llm-serving";

/// Timeout for waiting on phase transitions (e.g., Pending → Loading)
const PHASE_TIMEOUT: Duration = Duration::from_secs(120);
/// Timeout for longer operations (Serving phase, init container completion)
const LONG_TIMEOUT: Duration = DEFAULT_TIMEOUT;
/// Interval between polls when waiting for a condition
const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Expected HuggingFace model ID used in model-serving fixture
const EXPECTED_MODEL_ID: &str = "deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B";

/// Deploy a LatticeModel and verify the controller starts reconciling.
///
/// Injects curl-based connectivity-test sidecars into prefill and decode roles
/// so we can verify P/D cross-role traffic via log parsing (same pattern as
/// mesh bilateral agreement tests).
async fn test_model_deployment(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Deploying LatticeModel from fixture...");

    ensure_fresh_namespace(kubeconfig, MODEL_NAMESPACE).await?;

    let mut model: lattice_common::crd::LatticeModel = load_fixture_config("model-serving.yaml")?;
    inject_pd_connectivity_sidecars(&mut model);

    let yaml = serde_json::to_string(&model)
        .map_err(|e| format!("Failed to serialize model fixture: {e}"))?;
    apply_yaml(kubeconfig, &yaml).await?;

    // Wait for controller to pick up and transition to Loading
    wait_for_resource_phase(
        kubeconfig,
        "latticemodel",
        MODEL_NAMESPACE,
        MODEL_NAME,
        "Loading",
        PHASE_TIMEOUT,
    )
    .await?;

    info!("[Model] LatticeModel reached Loading phase");
    Ok(())
}

/// Inject curl-based connectivity-test sidecar containers into P/D roles.
///
/// Each sidecar continuously curls the peer role's service on the inference port
/// and logs ALLOWED/BLOCKED results with cycle markers, matching the mesh test
/// traffic generator pattern.
fn inject_pd_connectivity_sidecars(model: &mut lattice_common::crd::LatticeModel) {
    let inference_port = model
        .spec
        .routing
        .as_ref()
        .and_then(|r| r.port)
        .unwrap_or(8000);

    let roles: Vec<String> = model.spec.roles.keys().cloned().collect();
    let pd_roles: Vec<&str> = roles
        .iter()
        .filter(|r| r.as_str() == "prefill" || r.as_str() == "decode")
        .map(|s| s.as_str())
        .collect();

    if pd_roles.len() != 2 {
        return;
    }

    for role_name in &pd_roles {
        let peer = if *role_name == "prefill" {
            "decode"
        } else {
            "prefill"
        };
        let peer_svc = format!(
            "{}-{}.{}.svc.cluster.local",
            MODEL_NAME, peer, MODEL_NAMESPACE
        );
        let source = format!("{}-{}", MODEL_NAME, role_name);
        let target = format!("{}-{}", MODEL_NAME, peer);

        let script = format!(
            r#"while true; do
echo "{cycle_start}"
MAX_ATTEMPTS=3
ATTEMPT=0
RESULT="UNKNOWN"
while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    HTTP_CODE=$(curl -sk -o /dev/null -w "%{{http_code}}" --connect-timeout 2 --max-time 3 http://{peer_svc}:{port}/ 2>/dev/null; true)
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "204" ] || [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "404" ]; then
        RESULT="ALLOWED"
        break
    elif [ "$HTTP_CODE" = "403" ]; then
        RESULT="BLOCKED"
        break
    else
        ATTEMPT=$((ATTEMPT + 1))
        if [ $ATTEMPT -lt $MAX_ATTEMPTS ]; then sleep 1; fi
    fi
done
if [ "$RESULT" = "ALLOWED" ]; then
    echo "{source}->{target}:ALLOWED"
elif [ "$RESULT" = "BLOCKED" ]; then
    echo "{source}->{target}:BLOCKED"
else
    echo "{source}->{target}:BLOCKED (timeout)"
fi
echo "{cycle_end}"
sleep 5
done
"#,
            cycle_start = CYCLE_START_MARKER,
            cycle_end = CYCLE_END_MARKER,
            peer_svc = peer_svc,
            port = inference_port,
            source = source,
            target = target,
        );

        let sidecar = ContainerSpec {
            image: CURL_IMAGE.to_string(),
            command: Some(vec!["/bin/sh".to_string()]),
            args: Some(vec!["-c".to_string(), script]),
            resources: Some(ResourceRequirements {
                requests: Some(ResourceQuantity {
                    cpu: Some("50m".to_string()),
                    memory: Some("64Mi".to_string()),
                }),
                limits: Some(ResourceQuantity {
                    cpu: Some("200m".to_string()),
                    memory: Some("128Mi".to_string()),
                }),
            }),
            security: Some(SecurityContext {
                run_as_user: Some(100),
                apparmor_profile: Some("Unconfined".to_string()),
                allowed_binaries: vec!["*".to_string()],
                ..Default::default()
            }),
            volumes: {
                let mut v = BTreeMap::new();
                v.insert("/tmp".to_string(), Default::default());
                v
            },
            ..Default::default()
        };

        if let Some(role) = model.spec.roles.get_mut(*role_name) {
            role.entry_workload
                .containers
                .insert("connectivity-test".to_string(), sidecar);
        }
    }
}

/// Verify ModelServing resource was created with expected role structure
async fn test_model_serving_created(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Verifying ModelServing creation...");

    let serving_name = resolve_model_serving_name(kubeconfig, MODEL_NAMESPACE, MODEL_NAME).await?;

    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "modelservings.workload.serving.volcano.sh",
        &serving_name,
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

    // Verify decode role: replicas=1, workerReplicas=1, both templates present
    if decode["replicas"].as_u64() != Some(1) {
        return Err(format!(
            "decode role: expected replicas=1, got: {}",
            decode["replicas"]
        ));
    }
    if decode["workerReplicas"].as_u64() != Some(1) {
        return Err(format!(
            "decode role: expected workerReplicas=1, got: {}",
            decode["workerReplicas"]
        ));
    }
    if decode["entryTemplate"].is_null() {
        return Err("decode role: entryTemplate is null".to_string());
    }
    if decode["workerTemplate"].is_null() {
        return Err("decode role: workerTemplate is null".to_string());
    }

    // Verify prefill role: replicas=1, workerReplicas=0 (no workers), no workerTemplate
    if prefill["replicas"].as_u64() != Some(1) {
        return Err(format!(
            "prefill role: expected replicas=1, got: {}",
            prefill["replicas"]
        ));
    }
    if prefill["workerReplicas"].as_u64() != Some(0) {
        return Err(format!(
            "prefill role: expected workerReplicas=0, got: {}",
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
    // minRoleReplicas is always 1 for all roles (allows partial-capacity startup,
    // avoids Kthena immutability conflicts on SSA updates when replicas change)
    if min_replicas["decode"].as_u64() != Some(1) {
        return Err(format!(
            "gangPolicy: expected decode minRoleReplicas=1, got: {}",
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
    let scheduler = ms["spec"]["schedulerName"].as_str().unwrap_or_default();
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

/// Wait for the model to reach Serving phase (Kthena processes ModelServing)
async fn test_model_serving_phase(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Waiting for Serving phase (Kthena processing)...");

    wait_for_resource_phase(
        kubeconfig,
        "latticemodel",
        MODEL_NAMESPACE,
        MODEL_NAME,
        "Serving",
        LONG_TIMEOUT,
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

    // Verify workloadSelector matches the ModelServing resource name (model name + role suffix)
    let serving_name = resolve_model_serving_name(kubeconfig, MODEL_NAMESPACE, MODEL_NAME).await?;
    let match_labels = &ms["spec"]["workloadSelector"]["matchLabels"];
    let selector_value = match_labels["modelserving.volcano.sh/name"]
        .as_str()
        .unwrap_or_default();
    if selector_value != serving_name {
        return Err(format!(
            "ModelServer workloadSelector should match serving name '{}', got: '{}'",
            serving_name, selector_value
        ));
    }

    // Verify inference engine
    let engine = ms["spec"]["inferenceEngine"].as_str().unwrap_or_default();
    if engine != "vLLM" {
        return Err(format!(
            "ModelServer inferenceEngine should be 'vLLM', got: '{engine}'"
        ));
    }

    // Verify model name
    let model_field = ms["spec"]["model"].as_str().unwrap_or_default();
    if model_field != EXPECTED_MODEL_ID {
        return Err(format!(
            "ModelServer model should be '{EXPECTED_MODEL_ID}', got: '{model_field}'"
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
        return Err(
            "ModelServer pdGroup should be set (fixture has kvConnector + prefill/decode roles)"
                .to_string(),
        );
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
    let model_name = mr["spec"]["modelName"].as_str().unwrap_or_default();
    if model_name != EXPECTED_MODEL_ID {
        return Err(format!(
            "ModelRoute modelName should be '{EXPECTED_MODEL_ID}', got: '{model_name}'"
        ));
    }

    // Verify target model server name defaults to model name
    let target = &mr["spec"]["rules"][0]["targetModels"][0];
    let target_name = target["modelServerName"].as_str().unwrap_or_default();
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
    info!(
        "[Model] Verifying autoscaling resources (AutoscalingPolicy + AutoscalingPolicyBinding)..."
    );

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
    let target_value = metrics[0]["targetValue"]
        .as_str()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);
    if (target_value - 0.8).abs() > 0.001 {
        return Err(format!("Expected target value 0.8, got: {target_value}"));
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

    // Verify subTargets → Role/decode
    let sub_kind = target["target"]["subTargets"]["kind"]
        .as_str()
        .unwrap_or_default();
    if sub_kind != "Role" {
        return Err(format!(
            "Binding subTargets kind should be 'Role', got: '{sub_kind}'"
        ));
    }
    let sub_name = target["target"]["subTargets"]["name"]
        .as_str()
        .unwrap_or_default();
    if sub_name != "decode" {
        return Err(format!(
            "Binding subTargets name should be 'decode', got: '{sub_name}'"
        ));
    }

    // Verify min/max replicas
    if target["minReplicas"].as_u64() != Some(1) {
        return Err(format!(
            "Binding minReplicas should be 1, got: {}",
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

    info!("[Model] AutoscalingPolicyBinding verified: policyRef, target (ModelServing/{}, Role/decode), min=1, max=8, owner ref", MODEL_NAME);

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

/// Verify ModelServing pod templates have init containers and model volume for download injection
async fn test_model_serving_has_download_injection(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Verifying init containers and model volume on ModelServing...");

    let serving_name = resolve_model_serving_name(kubeconfig, MODEL_NAMESPACE, MODEL_NAME).await?;

    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "modelservings.workload.serving.volcano.sh",
        &serving_name,
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

        // Check init container "model-downloader" on entry template
        let empty = vec![];
        let init_containers = role["entryTemplate"]["spec"]["initContainers"]
            .as_array()
            .ok_or(format!(
                "role '{}' entryTemplate missing initContainers",
                role_name
            ))?;
        let has_downloader = init_containers
            .iter()
            .any(|c| c["name"] == "model-downloader");
        if !has_downloader {
            return Err(format!(
                "role '{}' entryTemplate missing model-downloader init container",
                role_name
            ));
        }

        // Check model-cache volume on entry template
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

        // Check volumeMount on entry template containers (readOnly at /models)
        let containers = role["entryTemplate"]["spec"]["containers"]
            .as_array()
            .ok_or(format!(
                "role '{}' entryTemplate missing containers",
                role_name
            ))?;
        for container in containers {
            let c_name = container["name"].as_str().unwrap_or("unknown");
            let mounts = container["volumeMounts"].as_array().unwrap_or(&empty);
            let has_mount = mounts.iter().any(|m| {
                m["name"] == "model-cache" && m["mountPath"] == "/models" && m["readOnly"] == true
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
            let worker_init = role["workerTemplate"]["spec"]["initContainers"]
                .as_array()
                .ok_or(format!(
                    "role '{}' workerTemplate missing initContainers",
                    role_name
                ))?;
            let worker_has_downloader = worker_init.iter().any(|c| c["name"] == "model-downloader");
            if !worker_has_downloader {
                return Err(format!(
                    "role '{}' workerTemplate missing model-downloader init container",
                    role_name
                ));
            }
        }

        info!(
            "[Model] Role '{}': init container + model volume verified",
            role_name
        );
    }

    info!("[Model] All role templates have model-downloader init container and model volume");
    Ok(())
}

/// Verify LatticeMeshMember resources include Kthena router and autoscaler as allowed callers,
/// opt out of ambient mesh, and use group-level selectors.
async fn test_model_mesh_members(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Verifying mesh members: ambient opt-out, group selector, Kthena callers...");

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

    let empty = vec![];

    for item in items {
        let mm_name = item["metadata"]["name"].as_str().unwrap_or("unknown");

        // Verify ambient: false (model serving opts out of Istio ambient)
        let ambient = item["spec"]["ambient"].as_bool().unwrap_or(true);
        if ambient {
            return Err(format!(
                "LatticeMeshMember '{}' should have ambient=false (model serving opts out)",
                mm_name
            ));
        }

        // Verify group-level selector uses lattice.dev/model label
        let target = &item["spec"]["target"];
        let selector = target["selector"].as_object().ok_or(format!(
            "LatticeMeshMember '{}' target should have a selector",
            mm_name
        ))?;
        let model_label = selector.get("lattice.dev/model").and_then(|v| v.as_str());
        if model_label != Some(MODEL_NAME) {
            return Err(format!(
                "LatticeMeshMember '{}' selector should have lattice.dev/model={}, got: {:?}",
                mm_name, MODEL_NAME, model_label
            ));
        }

        // Check that the Kthena router is in allowed_callers
        let callers = item["spec"]["allowedCallers"].as_array().unwrap_or(&empty);
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
        let ports = item["spec"]["ports"].as_array().unwrap_or(&empty);
        let has_inference_port = ports.iter().any(|p| p["port"].as_u64() == Some(8000));
        if !has_inference_port {
            return Err(format!(
                "LatticeMeshMember '{}' is missing inference port 8000",
                mm_name
            ));
        }

        // Verify allowPeerTraffic is enabled (PD disaggregation: kvConnector + prefill/decode)
        let peer_traffic = item["spec"]["allowPeerTraffic"].as_bool().unwrap_or(false);
        if !peer_traffic {
            return Err(format!(
                "LatticeMeshMember '{}' should have allowPeerTraffic=true for PD disaggregation",
                mm_name
            ));
        }

        info!(
            "[Model] MeshMember '{}': ambient=false, group selector, router allowed, inference port, peer traffic",
            mm_name
        );
    }

    // Verify decode role mesh members have the autoscaler as an allowed caller
    // (decode has autoscaling configured with entry_workload service port "metrics"=9090)
    let decode_entry_name = format!("{}-decode", MODEL_NAME);
    let decode_mm = items
        .iter()
        .find(|item| item["metadata"]["name"].as_str() == Some(&decode_entry_name))
        .ok_or(format!(
            "LatticeMeshMember '{}' not found for autoscaler verification",
            decode_entry_name
        ))?;

    let callers = decode_mm["spec"]["allowedCallers"]
        .as_array()
        .unwrap_or(&empty);
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

    let ports = decode_mm["spec"]["ports"].as_array().unwrap_or(&empty);
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

    info!("[Model] All mesh members correctly configured for Kthena routing, autoscaling, and PD disaggregation");
    Ok(())
}

const INFERENCE_TESTER_NAME: &str = "inference-tester";
const INFERENCE_TESTER_NAMESPACE: &str = "inference-tester";

/// Deploy a long-lived inference tester as a LatticeService that continuously
/// curls the decode entry service and emits cycle markers with
/// INFERENCE:VALID / INFERENCE:INVALID results.
async fn deploy_inference_tester(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Deploying inference tester LatticeService...");

    ensure_fresh_namespace(kubeconfig, INFERENCE_TESTER_NAMESPACE).await?;

    let svc_url = "http://kthena-router.kthena-system.svc.cluster.local/v1/completions";

    let script = format!(
        r#"while true; do
echo "{cycle_start}"
HTTP_CODE=$(curl -s -o /tmp/resp.txt -w '%{{http_code}}' -X POST "{url}" \
  -H "Content-Type: application/json" \
  -d '{{"model":"deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B","prompt":"hello","max_tokens":1}}' 2>/tmp/curl_err.txt)
CURL_EXIT=$?
RESP=$(cat /tmp/resp.txt 2>/dev/null)
CURL_ERR=$(cat /tmp/curl_err.txt 2>/dev/null)
if [ "$CURL_EXIT" -ne 0 ]; then
  echo "INFERENCE:INVALID curl_exit=$CURL_EXIT http=$HTTP_CODE err=$CURL_ERR"
elif echo "$RESP" | grep -q '"choices"'; then
  echo "INFERENCE:VALID http=$HTTP_CODE"
else
  echo "INFERENCE:INVALID http=$HTTP_CODE body=$RESP"
fi
echo "{cycle_end}"
sleep 5
done"#,
        url = svc_url,
        cycle_start = CYCLE_START_MARKER,
        cycle_end = CYCLE_END_MARKER,
    );

    let mut containers = BTreeMap::new();
    containers.insert(
        "curl".to_string(),
        ContainerSpec {
            image: CURL_IMAGE.clone(),
            command: Some(vec!["/bin/sh".to_string(), "-c".to_string(), script]),
            resources: Some(ResourceRequirements {
                requests: Some(ResourceQuantity {
                    cpu: Some("10m".to_string()),
                    memory: Some("16Mi".to_string()),
                }),
                limits: Some(ResourceQuantity {
                    cpu: Some("100m".to_string()),
                    memory: Some("64Mi".to_string()),
                }),
            }),
            security: Some(SecurityContext {
                run_as_user: Some(100),
                apparmor_profile: Some("Unconfined".to_string()),
                allowed_binaries: vec!["*".to_string()],
                ..Default::default()
            }),
            volumes: {
                let mut v = BTreeMap::new();
                v.insert("/tmp".to_string(), Default::default());
                v
            },
            ..Default::default()
        },
    );

    use lattice_common::crd::{DependencyDirection, ResourceSpec, ResourceType};

    let mut resources = BTreeMap::new();
    resources.insert(
        "kthena-router".to_string(),
        ResourceSpec {
            type_: ResourceType::Service,
            direction: DependencyDirection::Outbound,
            namespace: Some("kthena-system".to_string()),
            ..Default::default()
        },
    );

    let service = build_busybox_service(
        INFERENCE_TESTER_NAME,
        INFERENCE_TESTER_NAMESPACE,
        containers,
        resources,
    );

    deploy_and_wait_for_phase(
        kubeconfig,
        INFERENCE_TESTER_NAMESPACE,
        service,
        "Ready",
        None,
        LONG_TIMEOUT,
    )
    .await?;

    info!("[Model] Inference tester LatticeService deployed and Ready");
    Ok(())
}

/// Clean up the inference tester LatticeService.
async fn cleanup_inference_tester(kubeconfig: &str) {
    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "latticeservice",
        INFERENCE_TESTER_NAME,
        "-n",
        INFERENCE_TESTER_NAMESPACE,
        "--ignore-not-found",
    ])
    .await;
}

/// Verify the vLLM mock inference endpoint returns a valid OpenAI-compatible response.
///
/// Reads logs from the long-lived inference tester pod (deployed earlier in the
/// test sequence) and checks for INFERENCE:VALID results using the same
/// cycle-based log parsing pattern as mesh bilateral agreement tests.
async fn test_model_inference(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Verifying inference endpoint via inference tester logs...");

    let allowed_pattern = "INFERENCE:VALID";
    let blocked_pattern = "INFERENCE:INVALID";
    let kc = kubeconfig.to_string();

    wait_for_condition(
        "inference endpoint to return valid OpenAI-compatible response",
        LONG_TIMEOUT,
        Duration::from_secs(10),
        || {
            let kc = kc.clone();
            async move {
                let label =
                    format!("{}={}", lattice_common::LABEL_NAME, INFERENCE_TESTER_NAME);
                let logs = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "logs",
                    "-l",
                    &label,
                    "-c",
                    "curl",
                    "-n",
                    INFERENCE_TESTER_NAMESPACE,
                    "--tail",
                    "500",
                ])
                .await
                .unwrap_or_default();

                let cycle_count = logs.matches(CYCLE_END_MARKER).count();
                if cycle_count > 0 {
                    if let Some(true) =
                        parse_traffic_result(&logs, allowed_pattern, blocked_pattern)
                    {
                        info!(
                            "[Model] Inference endpoint verified: valid OpenAI-compatible \
                             response ({} cycles)",
                            cycle_count
                        );
                        return Ok(true);
                    }
                }
                Err(format!(
                    "inference not yet confirmed (cycles={})",
                    cycle_count
                ))
            }
        },
    )
    .await?;

    Ok(())
}

/// Verify P/D cross-role connectivity via curl sidecar logs.
///
/// Reads the connectivity-test sidecar logs from prefill and decode pods,
/// verifying that cross-role traffic is ALLOWED. Uses the same cycle-based
/// log parsing as mesh bilateral agreement tests.
async fn test_pd_cross_role_connectivity(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Verifying P/D cross-role connectivity via sidecar logs...");

    let directions: Vec<(&str, &str)> = vec![
        ("prefill", "llm-serving-prefill->llm-serving-decode"),
        ("decode", "llm-serving-decode->llm-serving-prefill"),
    ];

    let kc = kubeconfig.to_string();

    wait_for_condition(
        "P/D cross-role bidirectional traffic to be ALLOWED",
        DEFAULT_TIMEOUT,
        Duration::from_secs(10),
        || {
            let kc = kc.clone();
            let directions = directions.clone();
            async move {
                let mut failures = Vec::new();

                for (role, expected_pattern) in &directions {
                    let label_selector =
                        format!("app.kubernetes.io/name={}-{}", MODEL_NAME, role);
                    let logs = run_kubectl(&[
                        "--kubeconfig",
                        &kc,
                        "logs",
                        "-n",
                        MODEL_NAMESPACE,
                        "-l",
                        &label_selector,
                        "-c",
                        "connectivity-test",
                        "--tail",
                        "500",
                    ])
                    .await
                    .unwrap_or_default();

                    let cycle_count = logs.matches(CYCLE_END_MARKER).count();
                    if cycle_count == 0 {
                        failures.push(format!("{}: no complete cycles yet", role));
                        continue;
                    }

                    let allowed_pattern = format!("{}:ALLOWED", expected_pattern);
                    let blocked_pattern = format!("{}:BLOCKED", expected_pattern);

                    match parse_traffic_result(&logs, &allowed_pattern, &blocked_pattern) {
                        Some(true) => {
                            info!("[Model] {} cross-role traffic: ALLOWED", role);
                        }
                        Some(false) => {
                            failures.push(format!(
                                "{}: BLOCKED — mesh policy denying cross-role traffic",
                                role
                            ));
                        }
                        None => {
                            failures.push(format!("{}: no traffic result in logs", role));
                        }
                    }
                }

                if failures.is_empty() {
                    info!(
                        "[Model] P/D cross-role connectivity verified: \
                         bidirectional traffic ALLOWED"
                    );
                    Ok(true)
                } else {
                    Err(failures.join("; "))
                }
            }
        },
    )
    .await?;

    Ok(())
}

/// Verify model pods transition past Init state (init containers completed)
async fn test_download_lifecycle(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Waiting for model pods to complete init containers...");

    // Kthena labels pods with the ModelServing resource name (model name + role suffix).
    let serving_name = resolve_model_serving_name(kubeconfig, MODEL_NAMESPACE, MODEL_NAME).await?;
    let label_selector = format!("modelserving.volcano.sh/name={}", serving_name);
    let kc = kubeconfig.to_string();
    let ls = label_selector.clone();

    wait_for_condition(
        "model pods to complete init containers",
        LONG_TIMEOUT,
        POLL_INTERVAL,
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
                    "json",
                ])
                .await;

                match output {
                    Ok(json_str) => {
                        let pods: serde_json::Value = match serde_json::from_str(&json_str) {
                            Ok(v) => v,
                            Err(e) => {
                                info!("[Model] Could not parse pods JSON: {}", e);
                                return Ok(false);
                            }
                        };

                        let items = match pods["items"].as_array() {
                            Some(arr) => arr,
                            None => return Ok(false),
                        };

                        if items.is_empty() {
                            info!("[Model] No model pods found yet");
                            return Ok(false);
                        }

                        // Check that all pods have all init containers completed
                        let all_init_done = items.iter().all(|pod| {
                            let init_statuses = pod["status"]["initContainerStatuses"].as_array();
                            match init_statuses {
                                Some(statuses) => {
                                    !statuses.is_empty()
                                        && statuses.iter().all(|s| {
                                            // Init container is done when terminated with
                                            // exit code 0, or when ready is true
                                            s["state"]["terminated"]["exitCode"].as_i64() == Some(0)
                                                || s["ready"].as_bool() == Some(true)
                                        })
                                }
                                None => false,
                            }
                        });

                        let pod_count = items.len();
                        info!(
                            "[Model] Init container status: {}/{} pods completed",
                            items
                                .iter()
                                .filter(|pod| {
                                    pod["status"]["initContainerStatuses"]
                                        .as_array()
                                        .map(|statuses| {
                                            !statuses.is_empty()
                                                && statuses.iter().all(|s| {
                                                    s["state"]["terminated"]["exitCode"].as_i64()
                                                        == Some(0)
                                                        || s["ready"].as_bool() == Some(true)
                                                })
                                        })
                                        .unwrap_or(false)
                                })
                                .count(),
                            pod_count
                        );

                        Ok(all_init_done)
                    }
                    Err(e) => {
                        info!("[Model] Could not check pod init containers: {}", e);
                        Ok(false)
                    }
                }
            }
        },
    )
    .await?;

    info!("[Model] Download lifecycle verified: all init containers completed");
    Ok(())
}

/// Run all model integration tests
pub async fn run_model_tests(kubeconfig: &str) -> Result<(), String> {
    info!("[Model] Running LatticeModel integration tests on {kubeconfig}");

    let diag = DiagnosticContext::new(kubeconfig, MODEL_NAMESPACE);
    with_diagnostics(&diag, "Model", || async {
        setup_regcreds_infrastructure(kubeconfig).await?;
        run_model_test_sequence(kubeconfig).await?;
        cleanup_inference_tester(kubeconfig).await;
        delete_namespace(kubeconfig, INFERENCE_TESTER_NAMESPACE).await;
        delete_namespace(kubeconfig, MODEL_NAMESPACE).await;
        Ok(())
    })
    .await
}

async fn run_model_test_sequence(kubeconfig: &str) -> Result<(), String> {
    // Deploy the model (must complete before verification)
    test_model_deployment(kubeconfig).await?;

    // Deploy the inference tester early so it's ready by the time we need it.
    // It will keep curling until we read its logs after serving phase.
    deploy_inference_tester(kubeconfig).await?;

    // All resource verifications + download lifecycle run concurrently
    // (they are independent reads against already-created K8s resources)
    let harness = TestHarness::new("Model Tests");
    tokio::join!(
        harness.run("Download injection", || {
            test_model_serving_has_download_injection(kubeconfig)
        }),
        harness.run("ModelServing created", || {
            test_model_serving_created(kubeconfig)
        }),
        harness.run("Routing created", || {
            test_model_routing_created(kubeconfig)
        }),
        harness.run("Autoscaling created", || {
            test_model_autoscaling_created(kubeconfig)
        }),
        harness.run("Mesh members", || test_model_mesh_members(kubeconfig)),
        harness.run("Download lifecycle", || {
            test_download_lifecycle(kubeconfig)
        }),
    );
    harness.finish()?;

    // Serving phase depends on download lifecycle (init containers completed)
    test_model_serving_phase(kubeconfig).await?;

    // Inference requires pods to be running (Serving phase)
    test_model_inference(kubeconfig).await?;

    // P/D connectivity requires pods to be running (Serving phase)
    test_pd_cross_role_connectivity(kubeconfig).await?;

    cleanup_inference_tester(kubeconfig).await;

    info!("[Model] All LatticeModel integration tests passed!");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_model_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_model_tests(&resolved.kubeconfig).await.unwrap();
}
