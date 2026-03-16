#!/bin/bash
# Configure Proxmox host networking for Lattice multi-cluster deployment.
#
# Creates isolated bridges and VLANs for workload cluster separation:
#
#   vmbr0          - Main network (LAN-facing). Management cluster LB IPs here.
#   vmbr0 VLAN 100 - Management cluster nodes (not reachable from LAN).
#   vmbr1          - Workload cluster 1 (isolated, NAT to internet via vmbr0).
#   vmbr2          - Workload cluster 2 (isolated, NAT to internet via vmbr0).
#
# The management cluster nodes sit on VLAN 100 so kubelets aren't exposed
# to the home network. LB VIPs (kube-vip, Cilium LB-IPAM) stay on the
# untagged vmbr0 network so they're reachable from the LAN.
#
# Usage:
#   ssh root@<proxmox-host>
#   bash proxmox-network-setup.sh
#   # Review /etc/network/interfaces, then:
#   ifreload -a

set -euo pipefail

INTERFACES_FILE="/etc/network/interfaces"

# Check we're on a Proxmox host
if ! command -v pvesh &>/dev/null; then
    echo "ERROR: This script must be run on a Proxmox host."
    exit 1
fi

# Backup current config
cp "$INTERFACES_FILE" "${INTERFACES_FILE}.bak.$(date +%s)"
echo "Backed up $INTERFACES_FILE"

# Check if vmbr0 is VLAN-aware
if grep -q "bridge-vlan-aware yes" "$INTERFACES_FILE"; then
    echo "vmbr0 is already VLAN-aware"
else
    echo "Enabling VLAN-aware on vmbr0..."
    sed -i '/iface vmbr0/,/^$/ { /bridge-fd/a\    bridge-vlan-aware yes' "$INTERFACES_FILE"
    echo "  Added bridge-vlan-aware yes to vmbr0"
fi

# Enable IP forwarding (required for NAT)
if sysctl net.ipv4.ip_forward | grep -q "= 1"; then
    echo "IP forwarding already enabled"
else
    echo "Enabling IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi

# Add VLAN 100 interface for management cluster nodes
if grep -q "vmbr0.100" "$INTERFACES_FILE"; then
    echo "vmbr0.100 (mgmt node VLAN) already configured"
else
    echo "Adding vmbr0.100 (management cluster node VLAN)..."
    cat >> "$INTERFACES_FILE" <<'EOF'

auto vmbr0.100
iface vmbr0.100 inet static
    address 10.0.100.1/24
    post-up iptables -t nat -A POSTROUTING -s 10.0.100.0/24 -o vmbr0 -j MASQUERADE
    post-down iptables -t nat -D POSTROUTING -s 10.0.100.0/24 -o vmbr0 -j MASQUERADE
EOF
    echo "  vmbr0.100: 10.0.100.0/24 with NAT"
fi

# Add vmbr1 for workload cluster 1
if grep -q "vmbr1" "$INTERFACES_FILE"; then
    echo "vmbr1 (workload 1) already configured"
else
    echo "Adding vmbr1 (workload cluster 1)..."
    cat >> "$INTERFACES_FILE" <<'EOF'

auto vmbr1
iface vmbr1 inet static
    address 10.0.1.1/24
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    post-up iptables -t nat -A POSTROUTING -s 10.0.1.0/24 -o vmbr0 -j MASQUERADE
    post-down iptables -t nat -D POSTROUTING -s 10.0.1.0/24 -o vmbr0 -j MASQUERADE
EOF
    echo "  vmbr1: 10.0.1.0/24 with NAT"
fi

# Add vmbr2 for workload cluster 2
if grep -q "vmbr2" "$INTERFACES_FILE"; then
    echo "vmbr2 (workload 2) already configured"
else
    echo "Adding vmbr2 (workload cluster 2)..."
    cat >> "$INTERFACES_FILE" <<'EOF'

auto vmbr2
iface vmbr2 inet static
    address 10.0.2.1/24
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    post-up iptables -t nat -A POSTROUTING -s 10.0.2.0/24 -o vmbr0 -j MASQUERADE
    post-down iptables -t nat -D POSTROUTING -s 10.0.2.0/24 -o vmbr0 -j MASQUERADE
EOF
    echo "  vmbr2: 10.0.2.0/24 with NAT"
fi

echo ""
echo "Network configuration written to $INTERFACES_FILE"
echo ""
echo "Review the file, then apply with:"
echo "  ifreload -a"
echo ""
echo "Network layout:"
echo "  vmbr0          10.0.0.0/24   LAN (LB VIPs, kube-vip)"
echo "  vmbr0.100      10.0.100.0/24 Mgmt nodes (VLAN, not LAN-reachable)"
echo "  vmbr1           10.0.1.0/24   Workload 1 (isolated bridge)"
echo "  vmbr2           10.0.2.0/24   Workload 2 (isolated bridge)"
