#!/bin/bash
# Prepare a basic Proxmox VM template with Ubuntu cloud image
#
# NOTE: This creates a BASIC template with only qemu-guest-agent.
# For CAPI-ready templates with kubeadm/containerd pre-installed,
# use proxmox-build-template.sh instead.
#
# Usage: ./proxmox-prepare-template.sh [proxmox-host] [template-id] [storage] [bridge]

set -euo pipefail

PROXMOX_HOST="${1:-10.0.0.97}"
TEMPLATE_ID="${2:-9000}"
STORAGE="${3:-local-lvm}"
BRIDGE="${4:-vmbr0}"

echo "=== Proxmox Basic Template Preparation ==="
echo "Host: $PROXMOX_HOST"
echo "Template ID: $TEMPLATE_ID"
echo "Storage: $STORAGE"
echo ""

ssh "root@${PROXMOX_HOST}" bash -s "$TEMPLATE_ID" "$STORAGE" "$BRIDGE" << 'REMOTE_SCRIPT'
set -euo pipefail

TEMPLATE_ID="$1"
STORAGE="$2"
BRIDGE="$3"

# Check existing state
if qm status "$TEMPLATE_ID" &>/dev/null; then
    if qm config "$TEMPLATE_ID" | grep -q "^template: 1"; then
        echo "Converting template back to VM..."
        qm set "$TEMPLATE_ID" --template 0
    fi
else
    echo "Creating new VM from Ubuntu cloud image..."

    cd /var/lib/vz/template/iso
    IMAGE="jammy-server-cloudimg-amd64.img"
    [ -f "$IMAGE" ] || wget -q --show-progress "https://cloud-images.ubuntu.com/jammy/current/$IMAGE"

    qm create "$TEMPLATE_ID" \
        --name ubuntu-cloud-template \
        --memory 2048 \
        --cores 2 \
        --net0 "virtio,bridge=$BRIDGE" \
        --ostype l26 \
        --agent enabled=1

    qm importdisk "$TEMPLATE_ID" "$IMAGE" "$STORAGE"
    qm set "$TEMPLATE_ID" --scsihw virtio-scsi-pci --scsi0 "${STORAGE}:vm-${TEMPLATE_ID}-disk-0"
    qm set "$TEMPLATE_ID" --ide2 "${STORAGE}:cloudinit"
    qm set "$TEMPLATE_ID" --boot order=scsi0
    qm set "$TEMPLATE_ID" --serial0 socket --vga serial0
    qm resize "$TEMPLATE_ID" scsi0 20G
fi

# Configure temporary access
BRIDGE_IP=$(ip -4 addr show "$BRIDGE" | grep -oP 'inet \K[0-9.]+')
BRIDGE_CIDR=$(ip -4 addr show "$BRIDGE" | grep -oP 'inet [0-9.]+/\K[0-9]+')
GATEWAY=$(ip route | grep default | awk '{print $3}' | head -1)
TEMP_IP="${BRIDGE_IP%.*}.250"

TEMP_KEY="/tmp/lattice-key-$$"
ssh-keygen -t ed25519 -f "$TEMP_KEY" -N "" -q

echo "Configuring cloud-init (IP: $TEMP_IP)..."
qm set "$TEMPLATE_ID" --ciuser ubuntu --ipconfig0 "ip=${TEMP_IP}/${BRIDGE_CIDR},gw=${GATEWAY}" --sshkeys "$TEMP_KEY.pub"

[ "$(qm status "$TEMPLATE_ID" | awk '{print $2}')" != "running" ] && qm start "$TEMPLATE_ID"

echo "Waiting for SSH..."
for _ in {1..30}; do nc -z -w2 "$TEMP_IP" 22 2>/dev/null && break; sleep 3; done
sleep 5

echo "Installing qemu-guest-agent..."
ssh -i "$TEMP_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "ubuntu@$TEMP_IP" << 'INSTALL'
set -e
cloud-init status --wait
sudo apt-get update -qq
sudo apt-get install -y -qq qemu-guest-agent
sudo systemctl enable qemu-guest-agent
sudo cloud-init clean --logs
sudo truncate -s 0 /etc/machine-id
sudo rm -f /var/lib/dbus/machine-id
sudo shutdown -h now
INSTALL

echo "Waiting for shutdown..."
for _ in {1..30}; do [ "$(qm status "$TEMPLATE_ID" | awk '{print $2}')" = "stopped" ] && break; sleep 2; done

echo "Converting to template..."
qm set "$TEMPLATE_ID" --delete ciuser --delete sshkeys --delete ipconfig0 2>/dev/null || true
qm template "$TEMPLATE_ID"

rm -f "$TEMP_KEY" "$TEMP_KEY.pub"
echo "=== Template $TEMPLATE_ID ready ==="
REMOTE_SCRIPT

echo "Done!"
