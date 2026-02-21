Node-Level Registry Mirroring via CAPI                                                                                                                                                                             

 Context

 All infrastructure images (Cilium, Istio, cert-manager, etc.) reference upstream public registries. This causes Docker Hub rate limits during E2E tests and blocks enterprise air-gapped deployments. Instead of
 rewriting every Helm chart's image references, we inject containerd mirror configuration at the node level via CAPI machine configs. This covers all image pulls — Helm-rendered, programmatic addons, init
 containers, sidecars — with zero changes to bootstrap modules.

 The list of upstream registries is extracted at build time from the rendered Helm chart YAML (not hardcoded). lattice-infra/build.rs already renders all charts — we parse image: references and expose the unique
 registries as a compile-time constant.

 Every cluster is equal — any CAPI-provisioned cluster gets mirror config. The env var propagates through the bootstrap bundle so children and grandchildren all inherit it.

 Mechanism

 User sets spec.imageRegistry or LATTICE_IMAGE_REGISTRY env var
   → Operator reconciler resolves image_registry (CRD field || env var)
   → Provider builds CAPI manifests with containerd mirror files + preKubeadmCommands
   → CAPI provisions nodes with mirror config baked in
   → containerd redirects: quay.io/cilium/cilium → mirror.com/cilium/cilium
   → Optional kubelet credentials at /var/lib/kubelet/config.json

 Kubeadm clusters: CAPI files write containerd hosts.toml per upstream registry. A preKubeadmCommands entry enables containerd's config_path and restarts containerd before kubelet starts pulling.

 RKE2 clusters: A single /etc/rancher/rke2/registries.yaml handles mirror redirect + auth natively. No restart needed.

 Config sources: spec.imageRegistry on LatticeCluster CRD (per-cluster), LATTICE_IMAGE_REGISTRY env var (global default). CRD takes priority.

 ---
 Changes

 1. Extract upstream registries at build time

 File: crates/lattice-infra/build.rs (after all charts rendered, ~line 621)

 Add two helper functions and a post-render extraction step:

 fn extract_registry_host(image_ref: &str) -> String {
     let parts: Vec<&str> = image_ref.splitn(2, '/').collect();
     if parts.len() == 1 { return "docker.io".to_string(); }
     let first = parts[0];
     if first.contains('.') || first.contains(':') || first == "localhost" {
         first.to_string()
     } else {
         "docker.io".to_string()
     }
 }

 fn extract_registries_from_yaml(yaml: &str) -> std::collections::BTreeSet<String> {
     let mut registries = std::collections::BTreeSet::new();
     for line in yaml.lines() {
         let trimmed = line.trim();
         if let Some(rest) = trimmed.strip_prefix("image:") {
             let image_ref = rest.trim().trim_matches(|c| c == '"' || c == '\'');
             if !image_ref.is_empty() {
                 registries.insert(extract_registry_host(image_ref));
             }
         }
     }
     registries
 }

 After all std::fs::write(out_dir.join("...yaml"), yaml) calls, add:

 let yaml_files = [
     "cilium.yaml", "istio-base.yaml", "istio-cni.yaml", "istiod.yaml",
     "ztunnel.yaml", "external-secrets.yaml", "velero.yaml", "gpu-operator.yaml",
     "hami.yaml", "victoria-metrics-ha.yaml", "victoria-metrics-single.yaml",
     "keda.yaml", "tetragon.yaml", "cert-manager.yaml", "metrics-server.yaml",
 ];
 let mut all_registries = std::collections::BTreeSet::new();
 for file in &yaml_files {
     if let Ok(content) = std::fs::read_to_string(out_dir.join(file)) {
         all_registries.extend(extract_registries_from_yaml(&content));
     }
 }
 let registries_csv = all_registries.into_iter().collect::<Vec<_>>().join(",");
 println!("cargo:rustc-env=UPSTREAM_REGISTRIES={}", registries_csv);

 2. Expose registries from lattice-infra

 File: crates/lattice-infra/src/lib.rs (after line 37)

 /// Upstream container registries extracted at build time from all rendered Helm charts.
 /// Used by lattice-capi to generate containerd mirror configuration.
 pub fn upstream_registries() -> Vec<&'static str> {
     env!("UPSTREAM_REGISTRIES").split(',').filter(|s| !s.is_empty()).collect()
 }

 3. Add lattice-infra dependency to lattice-capi

 File: crates/lattice-capi/Cargo.toml (under [dependencies] Internal section)

 lattice-infra = { workspace = true }

 No circular dependency — lattice-infra depends only on lattice-common.

 4. CRD: Add image_registry and additional_mirrored_registries fields

 File: crates/lattice-common/src/crd/cluster.rs (after backups field, ~line 113)

 /// Private registry mirror host for infrastructure images.
 /// When set, CAPI-provisioned nodes configure containerd to pull from this
 /// mirror instead of upstream registries (docker.io, quay.io, etc.).
 /// Example: "myregistry.com" or "myregistry.com:5000"
 #[serde(default, skip_serializing_if = "Option::is_none")]
 pub image_registry: Option<String>,

 /// Additional upstream registries to mirror beyond the auto-detected
 /// infrastructure registries. Use this for application image registries
 /// (e.g., "ecr.aws", "my-harbor.internal:5000").
 #[serde(default, skip_serializing_if = "Option::is_none")]
 pub additional_mirrored_registries: Option<Vec<String>>,

 5. Add image_registry to CAPI config structs

 File: crates/lattice-capi/src/provider/mod.rs

 Add to ClusterConfig (line 261, after provider_type):
 pub image_registry: Option<String>,
 pub additional_mirrored_registries: Vec<String>,

 Add to ControlPlaneConfig (line 291, after ssh_authorized_keys):
 pub image_registry: Option<String>,
 pub additional_mirrored_registries: Vec<String>,

 Add resolver helpers (near the config structs):
 /// Resolve image registry from CRD field with env var fallback.
 pub fn resolve_image_registry(cluster: &LatticeCluster) -> Option<String> {
     cluster.spec.image_registry.clone()
         .or_else(|| std::env::var("LATTICE_IMAGE_REGISTRY").ok())
 }

 /// Get the full list of registries to mirror: auto-extracted + user-specified.
 pub fn resolve_mirrored_registries(cluster: &LatticeCluster) -> Vec<String> {
     let mut registries: Vec<String> = lattice_infra::upstream_registries()
         .iter().map(|s| s.to_string()).collect();
     if let Some(ref extra) = cluster.spec.additional_mirrored_registries {
         for r in extra {
             if !registries.contains(r) {
                 registries.push(r.clone());
             }
         }
     }
     registries
 }

 6. New registry mirror module

 New file: crates/lattice-capi/src/provider/registry.rs

 /// Generate containerd hosts.toml files for all registries to mirror.
 /// `registries` is the merged list (auto-extracted infra + user-specified).
 /// Returns CAPI file entries for /etc/containerd/certs.d/{registry}/hosts.toml
 pub fn generate_containerd_mirror_files(
     mirror: &str,
     registries: &[String],
     credentials: Option<&str>,
 ) -> Vec<serde_json::Value> {
     let mut files: Vec<serde_json::Value> = registries
         .iter()
         .map(|registry| {
             let content = format!(
                 "[host.\"https://{}\"]\n  capabilities = [\"pull\", \"resolve\"]\n",
                 mirror
             );
             serde_json::json!({
                 "content": content,
                 "owner": "root:root",
                 "path": format!("/etc/containerd/certs.d/{}/hosts.toml", registry),
                 "permissions": "0644"
             })
         })
         .collect();

     if let Some(creds) = credentials {
         files.push(serde_json::json!({
             "content": creds,
             "owner": "root:root",
             "path": "/var/lib/kubelet/config.json",
             "permissions": "0600"
         }));
     }

     files
 }

 /// Generate preKubeadmCommands to enable containerd mirror config_path + restart.
 pub fn generate_containerd_mirror_commands() -> Vec<String> {
     vec![
         "sed -i 's|config_path = \"\"|config_path = \"/etc/containerd/certs.d\"|' /etc/containerd/config.toml && systemctl restart containerd".to_string()
     ]
 }

 /// Generate RKE2 registries.yaml file entry for mirror config.
 pub fn generate_rke2_registries_file(
     mirror: &str,
     registries: &[String],
     credentials: Option<&str>,
 ) -> serde_json::Value {
     let mut mirrors = serde_json::Map::new();
     for registry in &registries {
         mirrors.insert(
             registry.to_string(),
             serde_json::json!({
                 "endpoint": [format!("https://{}", mirror)]
             }),
         );
     }

     let mut content = serde_json::json!({ "mirrors": mirrors });
     if let Some(creds) = credentials {
         content["configs"] = serde_json::json!({
             mirror: {
                 "auth": {
                     "identitytoken": creds
                 }
             }
         });
     }

     serde_json::json!({
         "content": serde_yaml::to_string(&content).unwrap_or_default(),
         "owner": "root:root",
         "path": "/etc/rancher/rke2/registries.yaml",
         "permissions": "0644"
     })
 }

 Add mod registry; to crates/lattice-capi/src/provider/mod.rs (near top, with other modules).

 Note: serde_yaml may need adding to lattice-capi Cargo.toml, OR we can format the YAML as a string literal without serde_yaml since the structure is simple. Evaluate at implementation time — if serde_yaml isn't
 already a dep, just format the string manually.

 7. Inject into kubeadm control plane generation

 File: crates/lattice-capi/src/provider/mod.rs, generate_kubeadm_control_plane() (line 915)

 Refactor the VIP files/commands section (lines 959-977) to use accumulator Vecs and add mirror config:

 // Build files and preKubeadmCommands accumulators (replaces current inline VIP logic)
 let mut files: Vec<serde_json::Value> = Vec::new();
 let mut pre_kubeadm_commands: Vec<String> = Vec::new();

 // Mirror config (must come before VIP — restarts containerd)
 if let Some(ref mirror) = cp_config.image_registry {
     files.extend(registry::generate_containerd_mirror_files(
         mirror, &cp_config.additional_mirrored_registries, None,
     ));
     pre_kubeadm_commands.extend(registry::generate_containerd_mirror_commands());
 }

 // VIP config
 if let Some(ref vip) = cp_config.vip {
     let kube_vip_content = generate_kube_vip_manifest(vip, &config.bootstrap)?;
     files.push(serde_json::json!({
         "content": kube_vip_content,
         "owner": "root:root",
         "path": "/etc/kubernetes/manifests/kube-vip.yaml",
         "permissions": "0644"
     }));
     let interface = &vip.interface;
     pre_kubeadm_commands.push(format!(
         r#"NODE_IP=$(ip -4 -o addr show {iface} | awk '{{print $4}}' | cut -d/ -f1 | head -1) && echo "KUBELET_EXTRA_ARGS=\"--node-ip=$NODE_IP\"" > /etc/default/kubelet"#,
         iface = interface
     ));
 }

 if !files.is_empty() {
     kubeadm_config_spec["files"] = serde_json::json!(files);
 }
 if !pre_kubeadm_commands.is_empty() {
     kubeadm_config_spec["preKubeadmCommands"] = serde_json::json!(pre_kubeadm_commands);
 }

 This replaces the current VIP block (lines 959-977). Same behavior when mirror not set.

 Note: config.registry_credentials doesn't exist on ClusterConfig yet — need to add it or resolve differently. Since registry credentials for node-level auth are a separate concern from operator pod
 imagePullSecrets, use REGISTRY_CREDENTIALS_FILE env var at the operator level and pass through. For now, pass None for credentials in the initial implementation and handle node-level auth as a follow-up.

 8. Inject into kubeadm worker config generation

 File: crates/lattice-capi/src/provider/mod.rs, generate_kubeadm_config_template_for_pool() (line 720)

 After building the spec (line 770-778), add mirror config:

 let mut spec = serde_json::json!({
     "template": {
         "spec": {
             "joinConfiguration": {
                 "nodeRegistration": node_registration
             }
         }
     }
 });

 if let Some(ref mirror) = config.image_registry {
     let mirror_files = registry::generate_containerd_mirror_files(
         mirror, &config.additional_mirrored_registries, None,
     );
     let mirror_commands = registry::generate_containerd_mirror_commands();
     spec["template"]["spec"]["files"] = serde_json::json!(mirror_files);
     spec["template"]["spec"]["preKubeadmCommands"] = serde_json::json!(mirror_commands);
 }

 9. Inject into RKE2 control plane generation

 File: crates/lattice-capi/src/provider/mod.rs, generate_rke2_control_plane() (line 1019)

 Add mirror registries.yaml file to the existing files Vec (after line 1027, before VIP):

 let mut files: Vec<serde_json::Value> = Vec::new();

 // Mirror config
 if let Some(ref mirror) = cp_config.image_registry {
     files.push(registry::generate_rke2_registries_file(
         mirror, &cp_config.additional_mirrored_registries, None,
     ));
 }

 // Existing VIP + SSH logic follows unchanged...

 10. Inject into RKE2 worker config generation

 File: crates/lattice-capi/src/provider/mod.rs, generate_rke2_config_template_for_pool() (line 791)

 After building the spec (line 829-839), add:

 let mut spec = serde_json::json!({...}); // existing

 if let Some(ref mirror) = config.image_registry {
     let file = registry::generate_rke2_registries_file(
         mirror, &config.additional_mirrored_registries, None,
     );
     spec["template"]["spec"]["files"] = serde_json::json!([file]);
 }

 11. Wire through each provider

 Files: docker.rs, aws.rs, proxmox.rs, openstack.rs in crates/lattice-capi/src/provider/

 Each provider constructs ClusterConfig and ControlPlaneConfig. Add image_registry field to both:

 ClusterConfig — same for all 4 providers:
 let config = ClusterConfig {
     // ... existing fields
     image_registry: resolve_image_registry(cluster),
     additional_mirrored_registries: resolve_mirrored_registries(cluster),
 };

 ControlPlaneConfig — same for all 4 providers:
 let cp_config = ControlPlaneConfig {
     // ... existing fields
     image_registry: resolve_image_registry(cluster),
     additional_mirrored_registries: resolve_mirrored_registries(cluster),
 };

 Locations:
 - docker.rs lines 294, 312
 - aws.rs lines 183, 193
 - proxmox.rs lines 238, 265
 - openstack.rs lines 173, 183

 12. Update tests

 File: crates/lattice-capi/src/provider/mod.rs (test module ~line 1420)

 Update test_config() helper (line 1424) to include new fields:
 fn test_config(bootstrap: BootstrapProvider) -> ClusterConfig<'static> {
     ClusterConfig {
         // ... existing
         image_registry: None,
         additional_mirrored_registries: vec![],
     }
 }

 Update all ControlPlaneConfig { ... } in tests (~10 instances) to include:
 image_registry: None,
 additional_mirrored_registries: vec![],

 13. CLI: Add --image-registry flag

 File: crates/lattice-cli/src/commands/install.rs

 Add CLI arg (near registry_credentials_file, ~line 73):
 #[arg(long, env = "LATTICE_IMAGE_REGISTRY")]
 pub image_registry: Option<String>,

 In deploy_lattice_operator() (~line 361), after add_bootstrap_env, conditionally add the env var using add_deployment_env:
 let with_env = add_bootstrap_env(s, &provider_str, provider_ref);
 let with_env = if let Some(ref registry) = self.image_registry {
     add_deployment_env(&with_env, &[("LATTICE_IMAGE_REGISTRY", registry)])
 } else {
     with_env
 };

 14. Thread through bootstrap bundle

 File: crates/lattice-cell/src/bootstrap/mod.rs

 In generate_operator_manifests() (line 309), add image_registry: Option<&str> parameter. In the env vars block (line 421-476), add:

 if let Some(registry) = image_registry {
     envs.push(EnvVar {
         name: "LATTICE_IMAGE_REGISTRY".to_string(),
         value: Some(registry.to_string()),
         ..Default::default()
     });
 }

 Update all call sites of generate_operator_manifests to pass the image_registry value (read from LATTICE_IMAGE_REGISTRY env var on the current operator).

 Also update the ManifestGenerator trait and BootstrapState to store/pass image_registry.

 ---
 Files Modified Summary

 ┌───────────────────────────────────────────────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │                     File                      │                                                      Change                                                      │
 ├───────────────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ crates/lattice-infra/build.rs                 │ Extract registries from rendered YAML, emit UPSTREAM_REGISTRIES env var                                          │
 ├───────────────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ crates/lattice-infra/src/lib.rs               │ Add upstream_registries() public function                                                                        │
 ├───────────────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ crates/lattice-capi/Cargo.toml                │ Add lattice-infra dependency                                                                                     │
 ├───────────────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ crates/lattice-common/src/crd/cluster.rs      │ Add image_registry: Option<String> and additional_mirrored_registries: Option<Vec<String>> to LatticeClusterSpec │
 ├───────────────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ crates/lattice-capi/src/provider/mod.rs       │ Add fields to structs, inject mirror config in 4 generate functions, add resolve_image_registry(), update tests  │
 ├───────────────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ crates/lattice-capi/src/provider/registry.rs  │ New — mirror file/command generation helpers                                                                     │
 ├───────────────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ crates/lattice-capi/src/provider/docker.rs    │ Populate image_registry in ClusterConfig + ControlPlaneConfig                                                    │
 ├───────────────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ crates/lattice-capi/src/provider/aws.rs       │ Same                                                                                                             │
 ├───────────────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ crates/lattice-capi/src/provider/proxmox.rs   │ Same                                                                                                             │
 ├───────────────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ crates/lattice-capi/src/provider/openstack.rs │ Same                                                                                                             │
 ├───────────────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ crates/lattice-cli/src/commands/install.rs    │ Add --image-registry CLI flag, set env var on operator deployment                                                │
 ├───────────────────────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ crates/lattice-cell/src/bootstrap/mod.rs      │ Add image_registry param to generate_operator_manifests, propagate env var                                       │
 └───────────────────────────────────────────────┴──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

 What Stays Unchanged

 - All bootstrap modules (cilium.rs, istio.rs, eso.rs, etc.) — still return &'static [String] with upstream registry refs
 - versions.toml — untouched
 - Default behavior — no mirror configured → no files/commands injected → identical to today
 - Existing registry_credentials — still handles operator pod imagePullSecrets

 Verification

 - cargo check — all crates compile
 - cargo test — existing tests pass (no mirror = no change, new fields default to None)
 - New unit tests in registry.rs:
   - generate_containerd_mirror_files() — verify hosts.toml content per registry, with and without credentials
   - generate_containerd_mirror_commands() — verify sed + restart command
   - generate_rke2_registries_file() — verify registries.yaml content
 - Verify build-time extraction: Run cargo build for lattice-infra and confirm UPSTREAM_REGISTRIES env var contains expected registries (docker.io, quay.io, registry.k8s.io, ghcr.io, nvcr.io)
 - CAPI manifest tests: Verify generate_kubeadm_control_plane() includes mirror files + commands when image_registry is set
 - Default path: No env var, no CRD field → no mirror files (identical to current)