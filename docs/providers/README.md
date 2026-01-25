# Infrastructure Providers

Lattice supports multiple infrastructure providers via Cluster API (CAPI).

## Supported Providers

| Provider | Status | Use Case | Load Balancer |
|----------|--------|----------|---------------|
| [Docker](docker.md) | Stable | Development/Testing | Host ports |
| [Proxmox](proxmox.md) | Stable | On-premises/SMB | kube-vip |
| [OpenStack](openstack.md) | Stable | Private/Public cloud | Octavia |
| [AWS](aws.md) | Stable | Public cloud | NLB |

## Provider Selection Guide

### Local Development
Use **Docker** for rapid iteration and testing. No credentials required.

### On-Premises / SMB
Use **Proxmox** for small-to-medium deployments with existing Proxmox infrastructure.
- Requires: API token, VM template, IP pool
- Best for: Home labs, small businesses, edge deployments

### Private Cloud
Use **OpenStack** for enterprise private clouds or OpenStack-based public clouds (OVH, Vexxhost, etc.).
- Requires: clouds.yaml, SSH key, image
- Best for: Enterprises with existing OpenStack, multi-tenant environments

### Public Cloud
Use **AWS** for scalable public cloud deployments.
- Requires: IAM credentials, SSH key, instance profiles
- Best for: Production workloads, auto-scaling, global distribution

## Quick Start

1. Choose your provider based on your infrastructure
2. Follow the provider-specific prerequisites
3. Create your cluster configuration
4. Run the installer:

```bash
lattice install --cluster cluster.yaml
```

## Common Configuration

All providers share these configuration options:

```yaml
spec:
  provider:
    kubernetes:
      version: "1.32.0"    # Kubernetes version
      bootstrap: kubeadm     # or rke2
      certSANs:              # Additional SANs for API server cert
        - "api.example.com"
    config:
      <provider>: {}         # Provider-specific config
  nodes:
    controlPlane: 3          # Number of control plane nodes
    workerPools:             # Named worker pools
      default:
        replicas: 5          # Number of worker nodes in this pool
  endpoints:
    host: "..."            # Optional: auto-discovered for cloud providers
    grpcPort: 50051
    bootstrapPort: 8443
```

## Future Providers

Planned but not yet implemented:
- **GCP** (Google Cloud Platform)
- **Azure** (Microsoft Azure)
