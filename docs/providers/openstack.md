# OpenStack Provider (CAPO)

Lattice uses [Cluster API Provider OpenStack (CAPO)](https://github.com/kubernetes-sigs/cluster-api-provider-openstack) for provisioning Kubernetes clusters on OpenStack clouds.

## Prerequisites

### 1. OpenStack Credentials (clouds.yaml)

Create a `clouds.yaml` file with your OpenStack credentials:

```yaml
clouds:
  openstack:
    auth:
      auth_url: https://auth.cloud.ovh.net/v3
      username: your-username
      password: your-password
      project_id: your-project-id
      project_name: your-project-name
      user_domain_name: Default
    region_name: GRA11
    interface: public
    identity_api_version: 3
```

Or use application credentials (recommended):

```yaml
clouds:
  openstack:
    auth:
      auth_url: https://auth.cloud.ovh.net/v3
      application_credential_id: your-app-cred-id
      application_credential_secret: your-app-cred-secret
    region_name: GRA11
    interface: public
    identity_api_version: 3
```

### 2. SSH Key Pair

Create or import an SSH key in OpenStack:

```bash
# Create new key
openstack keypair create lattice-key > lattice-key.pem
chmod 400 lattice-key.pem

# Or import existing
openstack keypair create --public-key ~/.ssh/id_rsa.pub lattice-key
```

### 3. Cloud Image

Upload or find a suitable cloud image:

```bash
# List available images
openstack image list

# Or upload Ubuntu cloud image
wget https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img
openstack image create "Ubuntu 22.04" \
  --disk-format qcow2 \
  --container-format bare \
  --file jammy-server-cloudimg-amd64.img \
  --public
```

### 4. External Network

Identify your external network for floating IPs and load balancers:

```bash
openstack network list --external
# Note the network ID
```

### 5. Credentials Secret

Create the CAPO credentials secret:

```bash
kubectl create secret generic openstack-cloud-config \
  -n capo-system \
  --from-file=clouds.yaml=/path/to/clouds.yaml \
  --from-file=cacert=/path/to/ca.crt  # optional, for self-signed certs
```

## Cluster Configuration

Example `LatticeCluster` for OpenStack:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: my-cluster
spec:
  provider:
    kubernetes:
      version: "1.32.0"
      bootstrap: kubeadm  # or rke2
    config:
      openstack:
        # Required
        externalNetworkId: "your-external-network-id"
        cpFlavor: "b2-30"           # 8 vCPU, 30GB RAM
        workerFlavor: "b2-15"       # 4 vCPU, 15GB RAM
        imageName: "Ubuntu 22.04"
        sshKeyName: "lattice-key"

        # Optional: cloud name in clouds.yaml (default: "openstack")
        # cloudName: "my-cloud"

        # Optional: secret reference (default: capo-system/openstack-cloud-config)
        # secretRef:
        #   name: "my-openstack-creds"
        #   namespace: "my-namespace"

        # Optional: DNS servers
        dnsNameservers:
          - "8.8.8.8"
          - "8.8.4.4"

        # Optional: node network CIDR
        nodeCidr: "10.6.0.0/24"

        # Optional: Octavia LB flavor
        # apiServerLoadBalancerFlavor: "small"

        # Optional: availability zones
        # cpAvailabilityZone: "nova"
        # workerAvailabilityZone: "nova"

        # Optional: root volumes (boot from volume)
        cpRootVolumeSizeGb: 50
        cpRootVolumeType: "high-speed"
        workerRootVolumeSizeGb: 50
        workerRootVolumeType: "classic"

        # Optional: security groups
        # managedSecurityGroups: true  # default
        # allowAllInClusterTraffic: false
  nodes:
    controlPlane: 3
    workers: 5
  endpoints:
    # host is auto-discovered from Octavia LB
    grpcPort: 50051
    bootstrapPort: 8443
    service:
      type: LoadBalancer
```

## Network Architecture

- **API Server**: Octavia Load Balancer (auto-provisioned)
- **Node Network**: CAPO creates a private network with router to external
- **Pod Network**: Cilium CNI

## Octavia (Load Balancer)

OpenStack uses Octavia for load balancing. Ensure it's available:

```bash
openstack loadbalancer list
# Should not error - Octavia is required
```

## Flavor Sizing

Recommended minimum flavors:

| Role | vCPU | RAM | Disk |
|------|------|-----|------|
| Control Plane | 4 | 8GB | 50GB |
| Worker | 2 | 4GB | 50GB |

Check available flavors:

```bash
openstack flavor list
```

## Cost Considerations (OVH Example)

- b2-7: ~$0.02/hour (2 vCPU, 7GB)
- b2-15: ~$0.04/hour (4 vCPU, 15GB)
- b2-30: ~$0.08/hour (8 vCPU, 30GB)
- Load Balancer: ~$10/month
- Floating IPs: Usually free or minimal

## Troubleshooting

### Authentication Errors

1. Verify clouds.yaml is correct: `openstack token issue`
2. Check secret is created in correct namespace
3. Ensure application credentials have sufficient permissions

### Network Issues

1. Verify external network exists and is routable
2. Check security groups allow required traffic
3. Ensure Octavia is operational

### Instance Launch Failures

1. Check OpenStack compute logs
2. Verify flavor and image exist
3. Ensure quota is sufficient: `openstack quota show`

### Octavia LB Not Ready

Octavia LBs can take a few minutes to provision:

```bash
openstack loadbalancer list
openstack loadbalancer show <lb-id>
```
