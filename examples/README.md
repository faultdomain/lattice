# Lattice Examples

Production-ready examples for provisioning clusters and deploying services with bilateral mesh agreements.

## Proxmox Multi-Cluster Network Setup

For bare-metal Proxmox deployments, run the network setup script on the Proxmox host before provisioning clusters:

```bash
scp scripts/infra/proxmox-network-setup.sh root@<proxmox-host>:
ssh root@<proxmox-host> bash proxmox-network-setup.sh
ssh root@<proxmox-host> ifreload -a
```

This creates the network layout for a DMZ + workload architecture:

```
LAN (home network)
 |
 +-- vmbr0 (10.0.0.0/24) -- LB VIPs, kube-vip (LAN-reachable)
 |    |
 |    +-- VLAN 100 (10.0.100.0/24) -- Mgmt cluster nodes (NOT LAN-reachable)
 |
 +-- vmbr1 (10.0.1.0/24) -- Workload cluster 1 (isolated, NAT only)
 |
 +-- vmbr2 (10.0.2.0/24) -- Workload cluster 2 (isolated, NAT only)
```

Management cluster nodes sit on VLAN 100 so kubelets and other node ports aren't exposed to the home network. LoadBalancer VIPs (kube-vip for the K8s API, Cilium LB-IPAM for services) remain on the untagged vmbr0 network so they're reachable from the LAN.

Workload clusters are fully isolated on their own bridges. They reach the internet via NAT through the Proxmox host. Cross-cluster traffic flows through Lattice's gRPC tunnel and Istio's east-west gateway.

See `cluster/proxmox-cluster.yaml` (DMZ/management) and `cluster/proxmox-workload.yaml` (isolated workload) for example LatticeCluster manifests using this layout.

## Cluster Provisioning

The `cluster/` directory contains a LatticeCluster manifest for local development using Docker:

```bash
lattice install -f examples/cluster/management-cluster.yaml
```

This will:
1. Create a temporary kind bootstrap cluster
2. Deploy CAPI and the Lattice operator
3. Create the InfraProvider and credentials automatically (based on `providerRef` and `provider.config`)
4. Provision the management cluster
5. Pivot CAPI resources to make it self-managing
6. Delete the bootstrap cluster

After install, the cluster is fully self-managing. The `parentConfig` section is included so it can optionally provision child clusters later.

## Webapp Deployment

The `webapp/` directory deploys a 5-service application with bilateral mesh agreements:

```
Browser -> [Ingress] -> frontend:80 -> api:3000 -> postgres:5432
                                              \-> redis:6379
                                     worker -> api:3000 (health)
                                            -> postgres:5432
                                            -> redis:6379
```

### Bilateral Agreement Matrix

| Service  | Outbound To          | Inbound From     |
|----------|----------------------|------------------|
| frontend | api                  | (ingress only)   |
| api      | postgres, redis      | frontend, worker |
| postgres | (none)               | api, worker      |
| redis    | (none)               | api, worker      |
| worker   | api, postgres, redis | (none)           |

Traffic is only allowed when **both sides agree**: the caller declares `direction: outbound` and the callee declares `direction: inbound`. All other traffic is denied by default (Cilium L4 + Istio L7).

### Secrets Setup

Create the backing secrets before deploying the webapp:

```bash
kubectl -n lattice-secrets create secret generic webapp-db-credentials \
  --from-literal=password=changeme

kubectl -n lattice-secrets create secret generic webapp-redis-credentials \
  --from-literal=password=changeme
```

### Deploy

```bash
kubectl apply -f examples/webapp/namespace.yaml
kubectl apply -f examples/webapp/postgres.yaml
kubectl apply -f examples/webapp/redis.yaml
kubectl apply -f examples/webapp/api.yaml
kubectl apply -f examples/webapp/worker.yaml
kubectl apply -f examples/webapp/frontend.yaml
```

### Access

Add `webapp.local` to `/etc/hosts` pointing to your ingress IP, then visit `http://webapp.local` to see the frontend page with live API status.

## Media Stack

The `media/` directory deploys a homelab media server stack with shared storage and bilateral mesh agreements. Designed for running on a home server (e.g., Dell PowerEdge) with a Lattice Docker cluster.

```
LAN/Internet -> nginx (host) -> media-ingress Gateway (172.18.x.x)
                                  ├─ jellyfin.home.arpa -> jellyfin:8096
                                  ├─ sonarr.home.arpa   -> sonarr:8989
                                  └─ nzbget.home.arpa   -> nzbget:6789

sonarr:8989 -> nzbget:6789 (download requests)
sonarr:8989 -> jellyfin:8096 (library refresh)
jellyfin:8096 -> repo.jellyfin.org (external, plugin updates)
nzbget:6789 -> egress-vpn (wireguard egress gateway)
```

### Bilateral Agreement Matrix

| Service      | Outbound To        | Inbound From |
|--------------|--------------------|--------------|
| jellyfin     | jellyfin-repo (ext)| sonarr       |
| sonarr       | nzbget, jellyfin   | (none)       |
| nzbget       | egress-vpn         | sonarr       |
| egress-vpn   | (none)             | nzbget       |

### Shared Volume

Jellyfin owns a 100Gi `media-storage` volume and grants access to sonarr and nzbget via `allowedConsumers`. Sonarr and nzbget reference it by ID without specifying a size.

### VPN Egress Gateway

Nzbget routes its download traffic through a wireguard egress gateway via bilateral mesh agreement. The gateway tunnels all traffic it receives through a wireguard VPN. Edit `egress-vpn.yaml` with your wireguard credentials before deploying.

### Prerequisites

- A Lattice management cluster running via Docker (see Cluster Provisioning above)
- A self-signed ClusterIssuer for TLS certificates:

```bash
# Check if one already exists
kubectl get clusterissuer

# If not, create one
cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: e2e-selfsigned
spec:
  selfSigned: {}
EOF
```

### Deploy

```bash
kubectl apply -f examples/media/namespace.yaml
kubectl apply -f examples/media/jellyfin.yaml
kubectl apply -f examples/media/sonarr.yaml
kubectl apply -f examples/media/egress-vpn.yaml
kubectl apply -f examples/media/nzbget.yaml
```

### Host Network Setup

The Lattice cluster runs inside Docker on the `172.18.0.0/16` network. Each service's `ingress` section compiles to a shared Gateway API Gateway (`media-ingress`) that gets a LoadBalancer IP on this Docker network. To make the services accessible from your LAN, set up nginx on the host as a reverse proxy.

**Find the gateway's LoadBalancer IP:**

```bash
kubectl get svc -n media media-ingress -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
# Example output: 172.18.255.10
```

**Install and configure nginx on the host:**

```bash
sudo apt install -y nginx

# Edit examples/media/nginx.conf — replace the proxy_pass IP with your gateway IP
sudo cp examples/media/nginx.conf /etc/nginx/sites-available/media
sudo ln -sf /etc/nginx/sites-available/media /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

### DNS Setup

On your LAN clients (or your home router's DNS), point `*.home.arpa` to the PowerEdge's LAN IP. If you don't run local DNS, add entries to `/etc/hosts` on each client:

```
# Replace 192.168.1.100 with your PowerEdge's LAN IP
192.168.1.100  jellyfin.home.arpa
192.168.1.100  sonarr.home.arpa
192.168.1.100  nzbget.home.arpa
```

### Access

- `http://jellyfin.home.arpa` — Jellyfin media server (initial setup wizard on first visit)
- `http://sonarr.home.arpa` — Sonarr TV management
- `http://nzbget.home.arpa` — NZBGet download client
