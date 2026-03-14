# Homelab: Edge Firewall + Backend Workloads

Two-cluster Proxmox setup with an edge cluster running HAProxy as a DMZ
and a backend cluster running all workloads.

## Architecture

```
Internet / Home Network
         |
+--------+------------------------------------------+
|  Edge Cluster (Parent, Proxmox node 1)             |
|                                                    |
|  haproxy-fw (LatticeService, 2 replicas)           |
|  +----------------------------------------------+ |
|  | main: haproxy        (reads /config)          | |
|  | sidecar: route-adapter (watches CRD, renders) | |
|  | shareProcessNamespace: true (SIGUSR2 reload)  | |
|  +----------------------------------------------+ |
|                                                    |
|  LatticeClusterRoutes CRD                          |
|  (populated from backend heartbeats)               |
+--------+------------------------------------------+
         | outbound gRPC
+--------+------------------------------------------+
|  Backend Cluster (Child, Proxmox node 2)           |
|  Self-managing after pivot                         |
|                                                    |
|  webapp: frontend, api, postgres, redis, worker    |
|  media:  jellyfin, sonarr, nzbget, egress-vpn      |
|                                                    |
|  Services with advertise: true push routes         |
|  to parent via heartbeat                           |
+----------------------------------------------------+
```

## How it works

- Backend services set `advertise: true` on ingress routes
- Agent discovers these + resolves Gateway LB IPs
- Routes pushed to parent via SubtreeState heartbeat
- Parent writes `LatticeClusterRoutes` CRD
- route-adapter sidecar watches the CRD, renders haproxy.cfg, reloads HAProxy

## Deployment

```bash
# 1. Edge cluster
kubectl apply -f edge-cluster.yaml
kubectl wait --for=condition=Ready latticecluster/edge --timeout=20m

# 2. Edge services
kubectl apply -f edge/namespace.yaml
kubectl apply -f edge/haproxy-fw.yaml

# 3. Backend cluster (provisioned by edge)
kubectl apply -f backend-cluster.yaml
kubectl wait --for=condition=Ready latticecluster/backend --timeout=30m

# 4. Backend workloads
export BK=$(kubectl get secret backend-kubeconfig -o jsonpath='{.data.value}' | base64 -d > /tmp/bk && echo /tmp/bk)
kubectl --kubeconfig=$BK apply -f backend/webapp/
kubectl --kubeconfig=$BK apply -f backend/media/

# 5. DNS — point all hostnames at the edge HAProxy LB IP
# <edge-lb-ip>  jellyfin.home.arpa sonarr.home.arpa nzbget.home.arpa webapp.home.arpa
```

## Route adapter

The `route-adapter/` directory contains a standalone Rust binary that
watches `LatticeClusterRoutes` CRDs and renders haproxy.cfg. It runs as
a sidecar in the haproxy-fw pod. Build and push it:

```bash
cd route-adapter
cargo build --release
docker build -t ghcr.io/evan-hines-js/lattice-route-adapter:latest .
docker push ghcr.io/evan-hines-js/lattice-route-adapter:latest
```
