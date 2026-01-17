#!/bin/bash
# E2E test with Proxmox provider (CAPMOX)
#
# Prerequisites:
# - Proxmox server with API access
# - VM template with cloud-init support (PROXMOX_TEMPLATE_ID)
# - SSH key at ~/.ssh/id_rsa.pub

set -e

export PROXMOX_URL='https://10.0.0.97:8006'
export PROXMOX_TOKEN='root@pam!lattice'
export PROXMOX_SECRET='2b3c8618-6a00-4848-8abf-d3af16cf2e83'
export PROXMOX_NODE='poweredge-lg'
export PROXMOX_TEMPLATE_ID='9000'
export PROXMOX_VIP='10.0.0.100'
export PROXMOX_VIP_INTERFACE='ens18'
export PROXMOX_IP_POOL='10.0.0.101,10.0.0.102,10.0.0.103'
export PROXMOX_GATEWAY='10.0.0.1'
export PROXMOX_SSH_KEY="$(cat ~/.ssh/id_ed25519.pub)"

export LATTICE_MGMT_PROVIDER=proxmox
export LATTICE_WORKLOAD_PROVIDER=proxmox
export LATTICE_MGMT_BOOTSTRAP=kubeadm
export LATTICE_WORKLOAD_BOOTSTRAP=rke2

cargo test -p lattice-cli --features provider-e2e --test e2e pivot_e2e -- --nocapture
