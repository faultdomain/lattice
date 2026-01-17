#!/bin/bash
# Clean Proxmox LVM and partition data from a disk
# Usage: ./clean-proxmox-disk.sh /dev/sdX
#
# WARNING: This destroys ALL data on the disk!

set -euo pipefail

DISK="${1:-}"

if [[ -z "$DISK" ]]; then
    echo "Usage: $0 /dev/sdX"
    echo ""
    echo "Available disks:"
    lsblk -d -o NAME,SIZE,MODEL | grep -v loop
    exit 1
fi

if [[ ! -b "$DISK" ]]; then
    echo "Error: $DISK is not a block device"
    exit 1
fi

echo "=== Current state of $DISK ==="
lsblk "$DISK"
echo ""
pvs 2>/dev/null | grep -E "$DISK|PV" || echo "No PVs found on $DISK"
echo ""

echo "WARNING: This will PERMANENTLY DESTROY all data on $DISK"
echo "         including LVM volumes, partitions, and filesystems!"
echo ""
read -p "Type 'YES' to continue: " confirm
[[ "$confirm" != "YES" ]] && { echo "Aborted."; exit 1; }

# 1. Deactivate any LVs on VGs that use this disk
echo ""
echo "=== Deactivating logical volumes ==="
for vg in $(pvs --noheadings -o vg_name "$DISK"* 2>/dev/null | sort -u | tr -d ' '); do
    if [[ -n "$vg" ]]; then
        echo "  Deactivating LVs in VG: $vg"
        lvchange -an "$vg" 2>/dev/null || true
    fi
done

# 2. Remove logical volumes
echo ""
echo "=== Removing logical volumes ==="
for vg in $(pvs --noheadings -o vg_name "$DISK"* 2>/dev/null | sort -u | tr -d ' '); do
    if [[ -n "$vg" ]]; then
        for lv in $(lvs --noheadings -o lv_name "$vg" 2>/dev/null | tr -d ' '); do
            echo "  Removing LV: $vg/$lv"
            lvremove -f "$vg/$lv" 2>/dev/null || true
        done
    fi
done

# 3. Remove volume groups
echo ""
echo "=== Removing volume groups ==="
for vg in $(pvs --noheadings -o vg_name "$DISK"* 2>/dev/null | sort -u | tr -d ' '); do
    if [[ -n "$vg" ]]; then
        echo "  Removing VG: $vg"
        vgremove -f "$vg" 2>/dev/null || true
    fi
done

# 4. Remove physical volumes
echo ""
echo "=== Removing physical volumes ==="
for pv in $(pvs --noheadings -o pv_name 2>/dev/null | grep "$DISK" | tr -d ' '); do
    echo "  Removing PV: $pv"
    pvremove -f "$pv" 2>/dev/null || true
done

# 5. Wipe filesystem signatures from partitions
echo ""
echo "=== Wiping filesystem signatures ==="
for part in "$DISK"*; do
    if [[ -b "$part" ]]; then
        echo "  Wiping: $part"
        wipefs -a "$part" 2>/dev/null || true
    fi
done

# 6. Wipe partition table
echo ""
echo "=== Wiping partition table ==="
sgdisk --zap-all "$DISK" 2>/dev/null || wipefs -a "$DISK"

# 7. Inform kernel of changes
partprobe "$DISK" 2>/dev/null || true

echo ""
echo "=== Done! Disk $DISK is now clean ==="
lsblk "$DISK"
