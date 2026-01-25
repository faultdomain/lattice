# Cross-Cluster Service Discovery

## Overview

Services in one cluster can depend on services in other clusters. This design enables discovery and routing across the cluster hierarchy using the existing agent-cell gRPC streams.

## Scale Target

- 500-1000 total services across all clusters
- 50-100 clusters in hierarchy
- <100ms cold lookup, <10ms cached
- Memory: ~5MB for full catalog

## Trust Model

### Single Trust Domain

All clusters in the Lattice hierarchy share a single trust root. This means:

- **Global SPIFFE Identity**: A certificate issued to `web` in Cluster B1 is cryptographically valid in Cluster B2
- **No Federation Complexity**: No need to exchange trust bundles between clusters
- **mTLS Just Works**: Cross-cluster connections use `ISTIO_MUTUAL` mode

```
                    ┌─────────────────┐
                    │   Root CA       │  ◄── Single trust root for entire hierarchy
                    │ (lattice.local) │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
         Intermediate   Intermediate   Intermediate
         CA (B)         CA (C)         CA (...)
              │              │
              ▼              ▼
         Cluster B      Cluster C
         workload       workload
         certs          certs
```

### Identity Format

SPIFFE IDs use the cluster name as the namespace identifier:

```
spiffe://lattice.local/ns/<cluster>/sa/<service>

Examples:
  spiffe://lattice.local/ns/cluster-b1/sa/web
  spiffe://lattice.local/ns/cluster-b2/sa/api
```

### Bilateral Validation

For v1 (gateway-level identity), `allowed_requesters` specifies which **clusters** can call, not individual services:

```rust
pub struct ServiceInfo {
    // ...
    // Clusters allowed to call this service
    pub allowed_requesters: Vec<String>,  // e.g., ["cluster-b1", "cluster-c1"]
}

// Validation checks cluster-level access
fn validate_bilateral(info: &ServiceInfo, query: &ServiceQuery) -> bool {
    info.allowed_requesters.contains(&query.requester_cluster)
}
```

For v2 (with JWT identity), this can be extended to per-service granularity:

```rust
// v2: Full SPIFFE identity format
pub allowed_requesters: Vec<String>,  // e.g., ["lattice.local/ns/cluster-b1/sa/web"]
```

### Cross-Cluster Identity Options

Istio Ambient doesn't support multi-cluster, so workload SPIFFE IDs don't automatically work across clusters. Three approaches:

#### Option A: Gateway-Level Identity (Recommended)

Each cluster's Gateway has a certificate from the shared Lattice CA. Cross-cluster mTLS happens at gateway level:

```
Cluster B1                              Cluster B2
┌──────────┐    ┌──────────────┐       ┌──────────────┐    ┌──────────┐
│   web    │───►│ Gateway      │──────►│ Gateway      │───►│   api    │
│          │    │ (presents    │ mTLS  │ (validates   │    │          │
│          │    │  cluster-b1  │       │  cluster-b1) │    │          │
│          │    │  identity)   │       │              │    │          │
└──────────┘    └──────────────┘       └──────────────┘    └──────────┘
                     │                        │
                     ▼                        ▼
              spiffe://lattice.local   Checks: is cluster-b1
              /ns/cluster-b1/sa/gateway  allowed to call api?
```

**Pros**: Simple, works with Ambient, no per-service cert management
**Cons**: Coarse-grained (cluster-level, not service-level identity)

The Gateway presents identity `spiffe://lattice.local/ns/<cluster>/sa/gateway`. AuthorizationPolicy validates at cluster granularity:

```rust
fn generate_cross_cluster_auth_policy(notification: &RouteNotification) -> AuthorizationPolicy {
    // Gateway-level identity - cluster granularity
    let caller_identity = format!(
        "spiffe://lattice.local/ns/{}/sa/gateway",
        notification.caller_cluster
    );
    // ... policy using caller_identity
}
```

#### Option B: JWT Forwarding

Workloads get JWTs from a central issuer (the agent). The JWT contains the full identity:

```
web pod → local agent → JWT signed by Lattice CA
                        {
                          "sub": "lattice.local/ns/cluster-b1/sa/web",
                          "aud": "lattice.local/ns/cluster-b2/sa/api"
                        }
```

The target Gateway validates the JWT before routing:

**Pros**: Per-service identity, fine-grained
**Cons**: More complex, need JWT infrastructure

#### Option C: Request Headers

The calling Gateway injects identity headers that the target trusts (because mTLS validated the gateway):

```
X-Lattice-Caller-Cluster: cluster-b1
X-Lattice-Caller-Service: web
X-Lattice-Caller-Namespace: default
```

**Pros**: Simple, works with any backend
**Cons**: Headers could be spoofed if not careful about trust boundaries

### Recommended: Option A for v1

Start with gateway-level identity. The bilateral agreement still enforces policy:

- **allowed_requesters** specifies which clusters can call: `["cluster-b1", "cluster-b3"]`
- Gateway mTLS validates the cluster identity
- Fine-grained per-service identity can be added later via Option B

### Security Considerations

| Risk | Mitigation |
|------|------------|
| Root CA compromise | All 50-100 clusters compromised. Use HSM-backed root, short-lived intermediates |
| Cluster ejection | Revoke intermediate CA. Push CRL to all clusters via agent stream |
| Service name collision | Full cluster identity validation prevents spoofing |
| Stale trust data | Periodic CRL refresh, intermediate CA rotation |
| Gateway compromise | Only affects one cluster; revoke that cluster's intermediate |

## Network Connectivity

Cross-cluster traffic uses **Gateway API + External DNS**. Istio Ambient doesn't support multicluster, so we handle routing at the Gateway API layer.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Cluster B1 (caller)                           │
│  ┌─────────┐                                      ┌─────────────────┐  │
│  │   web   │─────────────────────────────────────►│ Gateway         │  │
│  │  (pod)  │  calls api.cluster-b2.lattice.local  │ (egress)        │  │
│  └─────────┘                                      └────────┬────────┘  │
└───────────────────────────────────────────────────────────│───────────┘
                                                             │ mTLS
                                                             │ (DNS resolves via External DNS)
                                                             ▼
┌───────────────────────────────────────────────────────────│───────────┐
│                           Cluster B2 (target)              │           │
│  ┌─────────────────┐                                       │           │
│  │ Gateway         │◄──────────────────────────────────────┘           │
│  │ (ingress)       │                                                   │
│  │ + HTTPRoute     │────────────────────────────────────►┌─────────┐  │
│  └─────────────────┘                                     │   api   │  │
│                                                          │  (pod)  │  │
│                                                          └─────────┘  │
└───────────────────────────────────────────────────────────────────────┘
```

### DNS-Based Discovery

Each cluster runs External DNS, which publishes Gateway addresses:

```
api.cluster-b2.lattice.local  →  <Gateway LB IP of cluster-b2>
web.cluster-b1.lattice.local  →  <Gateway LB IP of cluster-b1>
```

### Gateway Endpoint Announcement

The `endpoints` field contains the DNS hostname for the service's gateway:

```rust
let announcement = ServiceAnnouncement {
    cluster: "cluster-b2".to_string(),
    namespace: "default".to_string(),
    name: "api".to_string(),
    endpoints: vec!["api.cluster-b2.lattice.local".to_string()],
    allowed_requesters: vec!["cluster-b1".to_string(), "cluster-c1".to_string()], // v1: cluster names
    deleted: false,
};
```

### Caller Side: ExternalName Service

The caller cluster creates an ExternalName Service pointing to the remote DNS:

```rust
fn generate_external_service(dep: &Dependency, remote: &ServiceQueryResponse) -> Service {
    Service {
        metadata: ObjectMeta {
            name: Some(format!("{}-remote", dep.name)),
            namespace: Some(dep.namespace.clone()),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            type_: Some("ExternalName".to_string()),
            external_name: Some(remote.endpoints[0].clone()), // api.cluster-b2.lattice.local
            ports: Some(vec![ServicePort {
                port: 443,
                target_port: Some(IntOrString::Int(443)),
                ..Default::default()
            }]),
            ..Default::default()
        }),
    }
}
```

### Target Side: Gateway + HTTPRoute

When the target cluster receives a RouteNotification, it creates:

```rust
fn generate_gateway_route(notification: &RouteNotification) -> HTTPRoute {
    HTTPRoute {
        metadata: ObjectMeta {
            name: Some(format!(
                "{}-cross-cluster",
                notification.target_service
            )),
            namespace: Some(notification.target_namespace.clone()),
            annotations: Some(btreemap! {
                // External DNS picks this up
                "external-dns.alpha.kubernetes.io/hostname".to_string() =>
                    format!("{}.{}.lattice.local",
                        notification.target_service,
                        notification.target_namespace)
            }),
            ..Default::default()
        },
        spec: HTTPRouteSpec {
            parent_refs: vec![ParentReference {
                name: "lattice-gateway".to_string(),
                namespace: Some("lattice-system".to_string()),
                ..Default::default()
            }],
            hostnames: vec![format!(
                "{}.{}.lattice.local",
                notification.target_service,
                notification.target_namespace
            )],
            rules: vec![HTTPRouteRule {
                backend_refs: vec![BackendRef {
                    name: notification.target_service.clone(),
                    port: Some(80),
                    ..Default::default()
                }],
                ..Default::default()
            }],
        },
    }
}
```

## Architecture

```
                    ┌─────────────────┐
                    │  Root Cluster   │
                    │ (Full Catalog)  │◄── Has ALL services from entire hierarchy
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
     ┌────────▼────────┐          ┌────────▼────────┐
     │   Cluster B     │          │   Cluster C     │
     │ (Catalog: B,B1, │          │ (Catalog: C,C1) │
     │  B2 + subtree)  │          │                 │
     └────────┬────────┘          └────────┬────────┘
              │                             │
      ┌───────┴───────┐                     │
      │               │                     │
┌─────▼─────┐  ┌─────▼─────┐         ┌─────▼─────┐
│ Cluster B1│  │ Cluster B2│         │ Cluster C1│
│ (web)     │  │ (api)     │         │ (db)      │
└───────────┘  └───────────┘         └───────────┘
```

**Key principle**: Announcements propagate UP to root (full catalog at each level). Route notifications fan DOWN to target clusters.

Each cluster maintains a **ServiceCatalog** containing all services from its subtree. Announcements bubble up automatically so the root has visibility of all services.

## Data Flow

### 1. Service Announcement (UP - child → root)

When a LatticeService is created/updated/deleted, the agent announces it to the parent, which forwards it to its parent, all the way to root:

```
┌───────────┐    announce     ┌───────────┐    announce     ┌───────────┐
│ Cluster C1│ ──────────────► │ Cluster C │ ──────────────► │   Root    │
│ (db)      │                 │           │                 │           │
└───────────┘                 └───────────┘                 └───────────┘
                                    │                             │
                                    ▼                             ▼
                              ServiceCatalog                ServiceCatalog
                              (has: db)                     (has: db, api, web, ...)
```

Every node in the path stores the announcement. Root has the complete catalog.

### 2. Service Query (UP - requester → root)

When a service has an Unknown dependency, the agent queries up the tree:

```
Cluster B1 (web needs api):
    │
    ▼ query("api", requester="web")
Cluster B: not found locally, forward up
    │
    ▼ query("api", requester="web")
Root: found! api is in Cluster B2
    │
    ▼ validate bilateral, return response
Response flows back down to B1
```

### 3. Route Notification (DOWN - root → target)

When a cross-cluster dependency is approved, the target cluster needs to know so it can expose the service via Gateway API:

```
Root receives query: "B1/web wants B2/api"
    │
    ├─► Validate bilateral ✓
    │
    ├─► Send RouteNotification DOWN to Cluster B2:
    │   "Cluster B1 will call your service 'api' from cluster B1"
    │
    └─► Return endpoints to B1
```

The target cluster (B2) creates:
- Gateway API HTTPRoute to expose the service
- Istio AuthorizationPolicy allowing the remote caller

### 4. Bilateral Agreement Validation

The node resolving the query (has service in catalog) validates the bilateral agreement:

```
Query: { service: "api", requester: "web", requester_cluster: "B1" }

Catalog lookup: api.allowed_requesters = ["web", "frontend"]

Check: "web" in allowed_requesters?
  → Yes: Return { found: true, access_allowed: true, endpoints: [...] }
        + Send RouteNotification to target cluster
  → No:  Return { found: true, access_allowed: false }
```

## Proto Messages

```protobuf
// Add to agent.proto

message ServiceAnnouncement {
  string cluster = 1;           // originating cluster
  string namespace = 2;
  string name = 3;
  repeated string endpoints = 4; // DNS hostnames (api.cluster-b2.lattice.local)
  repeated string allowed_requesters = 5; // v1: cluster names (cluster-b1), v2: full SPIFFE IDs
  bool deleted = 6;             // true = remove from catalog
}

message ServiceQuery {
  string namespace = 1;
  string name = 2;
  string requester_cluster = 3;  // cluster making the request
  string requester_service = 4;  // service making the request (for bilateral check)
}

message ServiceQueryResponse {
  bool found = 1;
  bool access_allowed = 2;       // bilateral agreement valid?
  string owner_cluster = 3;      // which cluster owns this service
  repeated string endpoints = 4;
  string error = 5;              // if found=false, why
}

// Route notification - sent DOWN to target cluster when cross-cluster dependency approved
message RouteNotification {
  string target_namespace = 1;   // namespace of the service being called
  string target_service = 2;     // service being called
  string caller_cluster = 3;     // cluster that will call this service
  string caller_service = 4;     // service that will call this
  bool revoked = 5;              // true = remove the route (dependency removed)
}

// Extend existing messages:

message AgentMessage {
  oneof payload {
    // ... existing ...
    ServiceAnnouncement service_announcement = 10;
    ServiceQuery service_query = 11;
  }
}

message CellCommand {
  oneof payload {
    // ... existing ...
    ServiceQueryResponse service_query_response = 10;
    ServiceAnnouncement service_announcement = 11; // forwarded from children
    RouteNotification route_notification = 12;     // tells cluster to expose service
  }
}
```

## Implementation

### ServiceCatalog (lattice-cluster/src/catalog.rs)

```rust
use dashmap::DashMap;
use std::collections::HashSet;

#[derive(Clone)]
pub struct ServiceInfo {
    pub cluster: String,
    pub namespace: String,
    pub name: String,
    pub endpoints: Vec<String>,
    pub allowed_requesters: Vec<String>,
}

pub struct ServiceCatalog {
    // Key: (namespace, name) - we track which cluster owns it
    services: DashMap<(String, String), ServiceInfo>,

    // Track which clusters are in each direct child's subtree
    // Key: direct child name, Value: all clusters in that subtree
    subtree_clusters: DashMap<String, HashSet<String>>,
}

impl ServiceCatalog {
    pub fn new() -> Self {
        Self {
            services: DashMap::new(),
            subtree_clusters: DashMap::new(),
        }
    }

    pub fn upsert(&self, announcement: ServiceAnnouncement) {
        let key = (announcement.namespace.clone(), announcement.name.clone());
        if announcement.deleted {
            self.services.remove(&key);
        } else {
            // Track which subtree this cluster belongs to
            self.track_cluster(&announcement.cluster);
            self.services.insert(key, ServiceInfo::from(announcement));
        }
    }

    fn track_cluster(&self, cluster: &str) {
        // Called when we receive an announcement - cluster is now known
        // The parent will track this in the appropriate subtree when forwarding
    }

    pub fn register_subtree_cluster(&self, direct_child: &str, cluster: &str) {
        self.subtree_clusters
            .entry(direct_child.to_string())
            .or_default()
            .insert(cluster.to_string());
    }

    pub fn cluster_in_subtree(&self, target: &str, direct_child: &str) -> bool {
        self.subtree_clusters
            .get(direct_child)
            .map(|set| set.contains(target))
            .unwrap_or(false)
    }

    pub fn query(&self, query: &ServiceQuery) -> Option<ServiceQueryResponse> {
        let key = (query.namespace.clone(), query.name.clone());
        self.services.get(&key).map(|info| {
            // v1: Check cluster-level access
            let access_allowed = info.allowed_requesters.contains(&query.requester_cluster);

            ServiceQueryResponse {
                found: true,
                access_allowed,
                owner_cluster: info.cluster.clone(),
                endpoints: info.endpoints.clone(),
                error: if !access_allowed {
                    format!("cluster {} not in allowed_requesters", query.requester_cluster)
                } else {
                    String::new()
                },
            }
        })
    }

    pub fn all_services(&self) -> Vec<ServiceInfo> {
        self.services.iter().map(|r| r.value().clone()).collect()
    }
}
```

### Cell Server Changes (lattice-cluster/src/agent/server.rs)

```rust
impl CellServer {
    async fn handle_agent_message(&self, cluster_name: &str, msg: AgentMessage) {
        match msg.payload {
            // ... existing handlers ...

            Some(Payload::ServiceAnnouncement(ann)) => {
                // Store in local catalog
                self.catalog.upsert(ann.clone());

                // Forward announcement UP to parent (propagates to root)
                if let Some(parent) = &self.parent_client {
                    parent.announce(ann).await;
                }
            }

            Some(Payload::ServiceQuery(query)) => {
                let response = self.resolve_service_query(&query).await;

                // If access was granted, notify the target cluster
                if response.found && response.access_allowed {
                    self.send_route_notification(&query, &response).await;
                }

                self.send_to_agent(cluster_name, CellCommand::ServiceQueryResponse(response));
            }
        }
    }

    async fn resolve_service_query(&self, query: &ServiceQuery) -> ServiceQueryResponse {
        // Check local catalog first
        if let Some(response) = self.catalog.query(query) {
            return response;
        }

        // Not found locally - forward to parent if we have one
        if let Some(parent) = &self.parent_client {
            return parent.query(query.clone()).await;
        }

        // No parent, service not found
        ServiceQueryResponse {
            found: false,
            access_allowed: false,
            owner_cluster: String::new(),
            endpoints: vec![],
            error: "service not found in hierarchy".into(),
        }
    }

    // Send route notification DOWN to the target cluster
    async fn send_route_notification(&self, query: &ServiceQuery, response: &ServiceQueryResponse) {
        let notification = RouteNotification {
            target_namespace: query.namespace.clone(),
            target_service: query.name.clone(),
            caller_cluster: query.requester_cluster.clone(),
            caller_service: query.requester_service.clone(),
            revoked: false,
        };

        // Route notification to the cluster that owns the service
        // This may need to traverse DOWN the tree to reach the target
        self.route_to_cluster(&response.owner_cluster, CellCommand::RouteNotification(notification)).await;
    }

    // Route a command down to a specific cluster
    async fn route_to_cluster(&self, target_cluster: &str, cmd: CellCommand) {
        // Check if target is a direct child
        if let Some(agent) = self.agents.get(target_cluster) {
            agent.send(cmd).await;
            return;
        }

        // Otherwise, find which child subtree contains the target
        // and forward to that child (it will recursively route down)
        for (child_name, agent) in self.agents.iter() {
            if self.catalog.cluster_in_subtree(target_cluster, child_name) {
                agent.send(cmd).await;
                return;
            }
        }
    }
}
```

### Agent Client Changes (lattice-cluster/src/agent/client.rs)

```rust
impl AgentClient {
    // Cache for resolved remote services
    cache: DashMap<(String, String), ServiceQueryResponse>,

    pub async fn announce(&self, service: &LatticeService) {
        let announcement = ServiceAnnouncement {
            cluster: self.cluster_name.clone(),
            namespace: service.metadata.namespace.clone().unwrap_or_default(),
            name: service.metadata.name.clone().unwrap_or_default(),
            endpoints: service.status.endpoints.clone(),
            allowed_requesters: extract_allowed_requesters(service),
            deleted: false,
        };
        self.send(AgentMessage::ServiceAnnouncement(announcement)).await;
    }

    pub async fn query(&self, namespace: &str, name: &str, requester: &str) -> ServiceQueryResponse {
        let key = (namespace.to_string(), name.to_string());

        // Check cache first
        if let Some(cached) = self.cache.get(&key) {
            return cached.clone();
        }

        // Query parent
        let query = ServiceQuery {
            namespace: namespace.to_string(),
            name: name.to_string(),
            requester_cluster: self.cluster_name.clone(),
            requester_service: requester.to_string(),
        };

        let response = self.query_parent(query).await;

        // Cache successful lookups
        if response.found {
            self.cache.insert(key, response.clone());
        }

        response
    }

    // Handle incoming RouteNotification from parent
    pub async fn handle_route_notification(&self, notification: RouteNotification) {
        if notification.revoked {
            // Remove the route
            self.remove_cross_cluster_route(&notification).await;
        } else {
            // Create Gateway API route + AuthorizationPolicy
            self.create_cross_cluster_route(&notification).await;
        }
    }

    async fn create_cross_cluster_route(&self, notification: &RouteNotification) {
        // 1. Create Gateway API HTTPRoute to expose the service
        let route = generate_gateway_route(notification);
        apply_resource(&self.client, &route).await;

        // 2. Create Istio AuthorizationPolicy allowing the remote caller
        let policy = generate_cross_cluster_auth_policy(notification);
        apply_resource(&self.client, &policy).await;
    }
}
```

### Gateway Route Generation (target cluster)

```rust
fn generate_gateway_route(notification: &RouteNotification) -> HTTPRoute {
    HTTPRoute {
        metadata: ObjectMeta {
            name: Some(format!(
                "{}-{}-from-{}",
                notification.target_namespace,
                notification.target_service,
                notification.caller_cluster
            )),
            namespace: Some(notification.target_namespace.clone()),
            ..Default::default()
        },
        spec: HTTPRouteSpec {
            parent_refs: vec![ParentReference {
                name: "mesh-gateway".to_string(),
                ..Default::default()
            }],
            hostnames: vec![format!(
                "{}.{}.global",
                notification.target_service,
                notification.target_namespace
            )],
            rules: vec![HTTPRouteRule {
                backend_refs: vec![BackendRef {
                    name: notification.target_service.clone(),
                    port: Some(80),
                    ..Default::default()
                }],
                ..Default::default()
            }],
        },
    }
}

fn generate_cross_cluster_auth_policy(notification: &RouteNotification) -> AuthorizationPolicy {
    // v1: Gateway-level identity (cluster granularity)
    // The gateway presents: spiffe://lattice.local/ns/<cluster>/sa/gateway
    let caller_gateway_identity = format!(
        "spiffe://lattice.local/ns/{}/sa/gateway",
        notification.caller_cluster
    );

    AuthorizationPolicy {
        metadata: ObjectMeta {
            name: Some(format!(
                "{}-allow-{}",
                notification.target_service,
                notification.caller_cluster
            )),
            namespace: Some(notification.target_namespace.clone()),
            ..Default::default()
        },
        spec: AuthorizationPolicySpec {
            selector: LabelSelector {
                match_labels: btreemap! {
                    "app".to_string() => notification.target_service.clone(),
                },
            },
            rules: vec![AuthRule {
                from: vec![Source {
                    // Gateway identity - validated via mTLS at gateway level
                    principals: vec![caller_gateway_identity],
                }],
                ..Default::default()
            }],
        },
    }
}
```

### Service Controller Integration (lattice-service/src/controller.rs)

```rust
async fn reconcile(service: Arc<LatticeService>, ctx: Arc<Context>) -> Result<Action> {
    // ... existing logic ...

    // Check for unknown dependencies
    let unknown_deps = get_unknown_dependencies(&service, &graph);

    for dep in unknown_deps {
        let response = ctx.agent_client.query(
            &dep.namespace,
            &dep.name,
            &service.metadata.name.unwrap_or_default(),
        ).await;

        if !response.found {
            // Dependency not found anywhere - requeue and wait
            return Ok(Action::requeue(Duration::from_secs(30)));
        }

        if !response.access_allowed {
            // Bilateral agreement not satisfied
            update_status(&service, "Denied", &format!(
                "Access to {} denied - not in allowed_requesters", dep.name
            )).await;
            return Ok(Action::requeue(Duration::from_secs(60)));
        }

        // Generate Istio ServiceEntry for the remote service
        let service_entry = generate_service_entry(&dep, &response);
        apply_resource(&ctx.client, &service_entry).await?;
    }

    // ... continue with policy generation ...
}
```

### ServiceEntry Generation

```rust
fn generate_service_entry(dep: &Dependency, remote: &ServiceQueryResponse) -> ServiceEntry {
    ServiceEntry {
        metadata: ObjectMeta {
            name: Some(format!("{}-{}-remote", dep.namespace, dep.name)),
            namespace: Some("istio-system".to_string()),
            ..Default::default()
        },
        spec: ServiceEntrySpec {
            hosts: vec![format!("{}.{}.global", dep.name, dep.namespace)],
            location: Location::MeshInternal,  // mTLS via mesh
            resolution: Resolution::Static,
            ports: vec![Port {
                number: 80,
                name: "http".to_string(),
                protocol: "HTTP".to_string(),
            }],
            endpoints: remote.endpoints.iter().map(|ep| {
                Endpoint {
                    address: ep.clone(),
                    ..Default::default()
                }
            }).collect(),
        },
    }
}
```

## Caching Strategy

**Simple approach for v1:**
- Cache never expires (services are stable)
- Cache invalidated on ServiceAnnouncement with `deleted=true`
- Full cache rebuild on agent reconnect (re-query all Unknown deps)

**Future optimization:**
- TTL-based refresh (query again after N minutes)
- Parent pushes updates when catalog changes

## Failure Modes

| Failure | Behavior |
|---------|----------|
| Parent disconnected | Use cached data, queries return cached or "unavailable" |
| Service deleted | Announcement with deleted=true propagates up; RouteNotification with revoked=true propagates down |
| Circular dependency | Detected at query time, return error |
| Root has no answer | Return "not found in hierarchy" |
| RouteNotification lost | Target cluster won't have route; caller retries query on connection failure |
| Target cluster offline | RouteNotification queued; route created when cluster reconnects |

## Summary: Bidirectional Flow

```
                         ANNOUNCEMENTS (UP)
                              ▲
                              │
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Cluster A  │    │    Root     │    │  Cluster B  │
│  (caller)   │◄───│  (catalog)  │───►│  (target)   │
└─────────────┘    └─────────────┘    └─────────────┘
       │                  │                  ▲
       │                  │                  │
       └──── QUERY ──────►│                  │
                          │                  │
       ◄─── RESPONSE ─────┘                  │
                          │                  │
                          └─ ROUTE NOTIFY ───┘
                                   │
                              (DOWN)
```

1. **UP**: Announcements bubble up so root knows all services
2. **QUERY**: Caller asks "where is X?" - travels up until found
3. **RESPONSE**: Endpoints + bilateral validation result flows back
4. **DOWN**: RouteNotification tells target cluster to expose the service

## Testing

E2E test flow:
1. Create Cluster A with service "web" that depends on "api"
2. Create Cluster B with service "api" that allows "web"
3. Verify "web" can discover "api" via parent (ServiceQuery → ServiceQueryResponse)
4. Verify ServiceEntry created in Cluster A (caller side)
5. Verify HTTPRoute + AuthorizationPolicy created in Cluster B (target side, via RouteNotification)
6. Delete "api", verify:
   - Cache cleared in Cluster A
   - Route removed in Cluster B (RouteNotification with revoked=true)
   - "web" status updates to Unknown

## File Changes

| File | Change |
|------|--------|
| `crates/lattice-proto/proto/agent.proto` | Add messages (~40 lines) |
| `crates/lattice-cluster/src/catalog.rs` | New file (~120 lines) |
| `crates/lattice-cluster/src/agent/server.rs` | Handle announcements/queries/routing (~80 lines) |
| `crates/lattice-cluster/src/agent/client.rs` | Announce/query/route handling (~80 lines) |
| `crates/lattice-service/src/controller.rs` | Resolve unknown deps (~30 lines) |
| `crates/lattice-service/src/resources/service_entry.rs` | Generate ServiceEntry (~50 lines) |
| `crates/lattice-service/src/resources/gateway_route.rs` | Generate HTTPRoute (~40 lines) |
| `crates/lattice-service/src/resources/cross_cluster_policy.rs` | Generate AuthorizationPolicy (~40 lines) |

**Total: ~480 lines of new code**
