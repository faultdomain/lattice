# Docker Provider (CAPD)

Lattice uses [Cluster API Provider Docker (CAPD)](https://github.com/kubernetes-sigs/cluster-api/tree/main/test/infrastructure/docker) for local development and testing.

## Prerequisites

### 1. Docker

Install Docker Desktop or Docker Engine:

```bash
# macOS
brew install --cask docker

# Linux (Ubuntu)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

### 2. Kind

The Docker provider uses Kind (Kubernetes in Docker) under the hood:

```bash
# macOS
brew install kind

# Linux
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind
```

### 3. Resources

Ensure Docker has sufficient resources:
- **Memory**: At least 8GB (16GB recommended)
- **CPUs**: At least 4 cores
- **Disk**: At least 20GB free

## Cluster Configuration

Example `LatticeCluster` for Docker:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: my-cluster
spec:
  provider:
    kubernetes:
      version: "1.32.0"
      bootstrap: kubeadm
    config:
      docker: {}  # No additional config needed
  nodes:
    controlPlane: 1
    workers: 2
  endpoints:
    host: "127.0.0.1"
    grpcPort: 50051
    bootstrapPort: 8443
```

## Limitations

The Docker provider is for **development and testing only**:

- Not suitable for production workloads
- Limited to single machine
- No real load balancer (uses host ports)
- No persistent storage across restarts

## Running E2E Tests

```bash
./scripts/test-docker.sh
```

## Troubleshooting

### Docker Not Running

```bash
# Check Docker status
docker info

# Start Docker (Linux)
sudo systemctl start docker
```

### Insufficient Resources

If clusters fail to start:
1. Increase Docker memory allocation
2. Remove unused containers: `docker system prune`
3. Reduce node count in cluster spec

### Port Conflicts

If ports are in use:
```bash
# Find process using port
lsof -i :50051

# Or use different ports in endpoints config
```
