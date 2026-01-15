# Proxmox Setup for Lattice CAPI

This guide covers setting up Proxmox VE to work with Lattice for provisioning Kubernetes clusters.

## Prerequisites

- Proxmox VE 7.x or 8.x running (yours is at `https://10.0.0.97:8006`)
- A management Kubernetes cluster with Lattice installed
- Network connectivity between the management cluster and Proxmox

## Step 1: Create Proxmox API Token

1. Log into Proxmox web UI at `https://10.0.0.97:8006`

2. Navigate to **Datacenter** → **Permissions** → **API Tokens**

3. Click **Add** and create a token:
   - **User**: `root@pam` (or create a dedicated user)
   - **Token ID**: `lattice`
   - **Privilege Separation**: **Unchecked** (token inherits user permissions)

4. Save the token - you'll get:
   - Token ID: `root@pam!lattice`
   - Secret: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` (shown once, save it!)

## Step 2: Create VM Template with Cloud-Init

CAPMOX requires a VM template with cloud-init for automated provisioning.

### Option A: Download Pre-built Cloud Image

```bash
# SSH into Proxmox
ssh root@10.0.0.97

# Download Ubuntu 22.04 cloud image
cd /var/lib/vz/template/iso
wget https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img

# Create a new VM (ID 9000 as template)
qm create 9000 --name ubuntu-cloud-template --memory 2048 --cores 2 --net0 virtio,bridge=vmbr0

# Import the cloud image as the VM's disk
qm importdisk 9000 jammy-server-cloudimg-amd64.img local-lvm

# Attach the disk to the VM
qm set 9000 --scsihw virtio-scsi-pci --scsi0 local-lvm:vm-9000-disk-0

# Add cloud-init drive
qm set 9000 --ide2 local-lvm:cloudinit

# Set boot order (use order= format for Proxmox 7+)
qm set 9000 --boot order=scsi0

# Enable QEMU guest agent
qm set 9000 --agent enabled=1

# IMPORTANT: Install qemu-guest-agent in the image
# The Ubuntu cloud image doesn't include it by default
# Start the VM, install the agent, then convert to template
qm start 9000
# Wait for VM to boot, then SSH in or use Proxmox console:
#   sudo apt update && sudo apt install -y qemu-guest-agent
#   sudo systemctl enable qemu-guest-agent
#   sudo shutdown -h now
# Then wait for shutdown and convert to template
qm template 9000
```

### Option B: Use Existing Template

If you already have a cloud-init enabled template, note its VM ID (e.g., `9000`).

**Requirements for the template:**
- Cloud-init installed and enabled
- QEMU guest agent installed
- Able to resize disk on first boot

## Step 3: Configure CAPMOX Credentials Secret

On your management cluster, create the credentials secret:

```bash
# Set your credentials
export PROXMOX_URL="https://10.0.0.97:8006"
export PROXMOX_TOKEN="root@pam!lattice"
export PROXMOX_SECRET="2b3c8618-6a00-4848-8abf-d3af16cf2e83"

# Create the secret in the CAPI provider namespace
kubectl create secret generic capmox-manager-credentials \
  --namespace capmox-system \
  --from-literal=url="$PROXMOX_URL" \
  --from-literal=token="$PROXMOX_TOKEN" \
  --from-literal=secret="$PROXMOX_SECRET"
```

## Step 4: Network Planning

Determine your IP allocation for Kubernetes nodes:

| Component | Example Value |
|-----------|---------------|
| Proxmox Node | `pve` (check in Proxmox UI) |
| Network Bridge | `vmbr0` |
| IP Range for K8s | `10.0.0.100-10.0.0.150` |
| Gateway | `10.0.0.1` |
| DNS | `10.0.0.1` or `8.8.8.8` |

## Step 5: Example LatticeCluster for Proxmox

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: my-proxmox-cluster
spec:
  provider:
    kubernetes:
      version: "1.31.0"
      bootstrap: kubeadm  # or rke2
      certSANs:
        - "10.0.0.100"
    config:
      proxmox:
        sourceNode: "pve"           # Your Proxmox node name
        templateId: 9000            # VM template ID from Step 2
        storage: "local-lvm"        # Storage backend
        bridge: "vmbr0"             # Network bridge

        # IP configuration
        ipv4Addresses:
          - "10.0.0.100"            # Control plane IP
          - "10.0.0.101"            # Worker 1 IP
          - "10.0.0.102"            # Worker 2 IP
        ipv4Prefix: 24
        ipv4Gateway: "10.0.0.1"
        dnsServers:
          - "10.0.0.1"

        # Control plane sizing
        cpCores: 4
        cpMemoryMib: 8192
        cpDiskSizeGb: 50

        # Worker sizing
        workerCores: 4
        workerMemoryMib: 8192
        workerDiskSizeGb: 100

  nodes:
    controlPlane: 1
    workers: 2

  # Required for parent/cell clusters
  endpoints:
    host: 10.0.0.100
    grpcPort: 50051
    bootstrapPort: 8443
    service:
      type: LoadBalancer
```

## Troubleshooting

### Check CAPMOX Controller Logs
```bash
kubectl logs -n capmox-system deployment/capmox-controller-manager -f
```

### Verify Credentials
```bash
# Test API access from your machine
curl -k "https://10.0.0.97:8006/api2/json/version" \
  -H "Authorization: PVEAPIToken=root@pam!lattice=YOUR_SECRET"
```

### Common Issues

1. **VM creation fails**: Check Proxmox storage has enough space
2. **Network unreachable**: Verify bridge name and IP range don't conflict
3. **Cloud-init not running**: Ensure template has cloud-init installed
4. **Permission denied**: API token needs PVEAdmin or root privileges

## Running E2E Tests with Proxmox

Set the required environment variables and run the tests:

```bash
# Required: CAPMOX credentials (for the CAPI provider)
export PROXMOX_URL="https://10.0.0.97:8006"
export PROXMOX_TOKEN="root@pam!lattice"
export PROXMOX_SECRET="2b3c8618-6a00-4848-8abf-d3af16cf2e83"

# Required: Cluster configuration
export PROXMOX_NODE="pve"                    # Your Proxmox node name
export PROXMOX_TEMPLATE_ID="9000"            # Cloud-init template VM ID
export PROXMOX_IP_POOL="10.0.0.100,10.0.0.101,10.0.0.102,10.0.0.103"  # IPs for nodes
export PROXMOX_GATEWAY="10.0.0.1"

# Optional (have defaults)
export PROXMOX_STORAGE="local-lvm"           # Storage backend
export PROXMOX_BRIDGE="vmbr0"                # Network bridge
export PROXMOX_DNS="10.0.0.1"                # DNS server

# Select Proxmox as the provider for E2E tests
export E2E_MGMT_PROVIDER="proxmox"
export E2E_WORKLOAD_PROVIDER="proxmox"

# Run the E2E test
cargo test --package lattice-cli --features provider-e2e test_configurable_provider_pivot -- --nocapture
```

## Quick Reference

| Item | Value |
|------|-------|
| Proxmox URL | `https://10.0.0.97:8006` |
| API Token Format | `user@realm!tokenid` |
| Template ID | `9000` (or your template) |
| CAPI Provider | `infrastructure-proxmox` v0.7.5 |
| Credentials Secret | `capmox-manager-credentials` |
