# Proxmox Provider (CAPMOX)

Lattice uses [Cluster API Provider Proxmox (CAPMOX)](https://github.com/ionos-cloud/cluster-api-provider-proxmox) for provisioning Kubernetes clusters on Proxmox VE.

## Prerequisites

### 1. Proxmox API Token

Create an API token in Proxmox:

1. Go to Datacenter → Permissions → API Tokens
2. Add a new token for your user (e.g., `root@pam!lattice`)
3. Note: Uncheck "Privilege Separation" for full access, or assign appropriate roles

Export credentials:

```bash
export PROXMOX_URL="https://10.0.0.97:8006"
export PROXMOX_TOKEN="root@pam!lattice"
export PROXMOX_SECRET="your-token-secret"
```

### 2. VM Template

Create a cloud-init enabled VM template:

```bash
# Download Ubuntu cloud image
wget https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img

# Create VM
qm create 9000 --memory 2048 --cores 2 --name ubuntu-template --net0 virtio,bridge=vmbr0

# Import disk
qm importdisk 9000 jammy-server-cloudimg-amd64.img local-lvm

# Configure VM
qm set 9000 --scsihw virtio-scsi-pci --scsi0 local-lvm:vm-9000-disk-0
qm set 9000 --ide2 local-lvm:cloudinit
qm set 9000 --boot c --bootdisk scsi0
qm set 9000 --serial0 socket --vga serial0
qm set 9000 --agent enabled=1

# Convert to template
qm template 9000
```

### 3. Storage

Ensure you have sufficient storage on your Proxmox cluster:
- VM disks (local-lvm or Ceph)
- ISO images for cloud-init

### 4. Networking

Configure a bridge network (e.g., `vmbr0`) with:
- DHCP server or static IP pool
- Internet access for downloading container images

### 5. kube-vip Configuration

Proxmox uses kube-vip for the API server VIP. Reserve an IP in your network for this.

## Cluster Configuration

Example `LatticeCluster` for Proxmox:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: my-cluster
spec:
  provider:
    kubernetes:
      version: "1.32.0"
      bootstrap: rke2  # recommended for Proxmox
    config:
      proxmox:
        # Template configuration
        sourceNode: "pve"           # Proxmox node name
        templateId: 9000            # VM template ID

        # Network configuration
        bridge: "vmbr0"

        # IP allocation
        ipv4Pool:
          start: "10.0.0.100"
          end: "10.0.0.150"
          gateway: "10.0.0.1"
          prefix: 24

        # Optional: IPv6
        # ipv6Pool:
        #   start: "2001:db8::100"
        #   end: "2001:db8::1ff"
        #   gateway: "2001:db8::1"
        #   prefix: 64

        # Resource allocation
        cpCores: 4
        cpMemoryMb: 8192
        cpDiskSizeGb: 50
        workerCores: 2
        workerMemoryMb: 4096
        workerDiskSizeGb: 50

        # Storage
        storage: "local-lvm"        # or "ceph-pool"

        # Optional: placement
        # allowedNodes:
        #   - "pve1"
        #   - "pve2"
  nodes:
    controlPlane: 3
    workers: 5
  endpoints:
    host: "10.0.0.99"  # kube-vip VIP address
    grpcPort: 50051
    bootstrapPort: 8443
    service:
      type: LoadBalancer
  networking:
    lbPool:
      start: "10.0.0.200"
      end: "10.0.0.220"
```

## Network Architecture

- **API Server**: kube-vip provides a floating VIP for HA
- **Load Balancing**: Cilium LB-IPAM for service LoadBalancers
- **Pod Network**: Cilium CNI with native routing

## Storage Options

### Local LVM (Default)
- Simple setup, single-node storage
- Good for development/testing

### Ceph
- Distributed storage for HA
- Required for live migration
- Configure with `storage: "your-ceph-pool"`

## Troubleshooting

### VM Creation Fails

Check Proxmox task logs in the web UI. Common issues:
- Insufficient storage space
- Template not found
- Network bridge misconfigured

### Nodes Not Joining

1. Check cloud-init logs: `cat /var/log/cloud-init-output.log`
2. Verify network connectivity to API server VIP
3. Ensure kube-vip IP is not in use

### kube-vip Issues

If the VIP is unreachable:
1. Check kube-vip pod logs: `kubectl logs -n kube-system -l app=kube-vip`
2. Verify ARP is working: `arping -I eth0 <vip>`
3. Ensure VIP is in the same subnet as node IPs

### IPAM Exhaustion

If you run out of IPs:
1. Extend the pool range in `ipv4Pool`
2. Clean up old IPAddressClaim resources
