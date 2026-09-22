#!/usr/bin/env bash
# ==============================================================================
# df-mount: Forensic Disk Mount & Target Unblock Utility for df-nix
# Designed for DFIR field operations in synergy with dfdisk
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

is_system_device() {
    local dev="$1"
    [[ -b "$dev" ]] || return 1

    # Check for live ISO boot media label
    local label
    label=$(lsblk -no LABEL "$dev" 2>/dev/null || true)
    if [[ "$label" == "DFNIX_LIVE" ]]; then
        return 0
    fi

    # Determine root parent disk if a partition was passed
    local root_dev="$dev"
    local pkname
    pkname=$(lsblk -no PKNAME "$dev" 2>/dev/null || true)
    while [[ -n "$pkname" && -b "/dev/$pkname" ]]; do
        root_dev="/dev/$pkname"
        pkname=$(lsblk -no PKNAME "$root_dev" 2>/dev/null || true)
    done

    # Inspect all mountpoints across the entire device hierarchy
    local m
    while IFS= read -r m; do
        [[ -z "$m" ]] && continue
        # Ignore desktop user automounts under /run/media or /run/user
        if [[ "$m" == "/run/media/"* || "$m" == "/run/user/"* ]]; then
            continue
        fi
        if [[ "$m" == "/" || "$m" == "/boot"* || "$m" == "/nix"* || "$m" == "/iso"* || "$m" == "/sysroot"* || "$m" == "/run"* || "$m" == "[SWAP]" ]]; then
            return 0
        fi
    done < <(lsblk -no MOUNTPOINTS "$root_dev" 2>/dev/null)

    return 1
}

cmd_status() {
    echo -e "${BOLD}${CYAN}=== df-nix Forensic Storage Matrix ===${NC}"
    printf "%-12s %-6s %-8s %-10s %-18s %-22s %s\n" "DEVICE" "RO" "SIZE" "TYPE" "FSTYPE" "MOUNTPOINT" "MODEL / SERIAL"
    echo "------------------------------------------------------------------------------------------------------"

    local parse_stream
    if command -v jq >/dev/null 2>&1; then
        parse_stream='jq -r '\''
            def walk_devs: .[] | (., (select(.children != null) | .children | walk_devs));
            [.blockdevices | walk_devs] | .[] |
            [
                .name // "",
                (if .ro then "1" else "0" end),
                .size // "",
                .type // "",
                .fstype // "",
                (.mountpoint // (.mountpoints[0] // "")),
                .model // "",
                .serial // ""
            ] | map(tostring | gsub("\\|"; "/")) | join("|")
        '\'
    else
        parse_stream='python3 -c '\''
import sys, json
data = json.load(sys.stdin)
def walk(devs):
    for d in devs:
        mounts = d.get("mountpoints") or []
        mp = d.get("mountpoint") or (mounts[0] if mounts else "")
        ro = "1" if d.get("ro") else "0"
        fields = [
            d.get("name") or "",
            ro,
            d.get("size") or "",
            d.get("type") or "",
            d.get("fstype") or "",
            mp,
            d.get("model") or "",
            d.get("serial") or ""
        ]
        clean_fields = [str(f).replace("|", "/") for f in fields]
        print("|".join(clean_fields))
        if "children" in d:
            walk(d["children"])
walk(data.get("blockdevices", []))
'\'
    fi

    while IFS='|' read -r name ro size type fstype mountpoint model serial; do
        [[ -z "$name" ]] && continue
        dev_path="/dev/$name"
        ro_status="${GREEN}RO (Locked)${NC}"
        if [[ "$ro" == "0" || "$ro" == "false" ]]; then
            ro_status="${RED}RW (Target)${NC}"
        fi

        tag=""
        if is_system_device "$dev_path"; then
            tag=" ${YELLOW}[SYSTEM]${NC}"
        elif [[ "$mountpoint" == *"/media/evidence"* ]]; then
            tag=" ${GREEN}[EVIDENCE]${NC}"
        elif [[ "$mountpoint" == *"/media/target"* ]]; then
            tag=" ${RED}[TARGET]${NC}"
        fi

        local model_serial=""
        [[ -n "$model" ]] && model_serial="$model"
        [[ -n "$serial" ]] && model_serial="${model_serial:+$model_serial }$serial"
        [[ -z "$model_serial" ]] && model_serial="-"

        printf "%-12s %-15b %-8s %-10s %-18s %-31b %s\n" \
            "$name" "$ro_status" "$size" "$type" "${fstype:--}" "${mountpoint:--}$tag" "$model_serial"
    done < <(lsblk -J -o NAME,RO,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL,SERIAL 2>/dev/null | eval "$parse_stream")
}

cmd_mount_evidence() {
    local dev="$1"
    local mount_target="${2:-}"

    if [[ ! -b "$dev" ]]; then
        echo -e "${RED}[!] Error: $dev is not a valid block device.${NC}" >&2
        exit 1
    fi

    if is_system_device "$dev"; then
        echo -e "${RED}[⛔] ABORT: $dev belongs to the operating system! Action blocked.${NC}" >&2
        exit 1
    fi

    # 1. Enforce Kernel Driver Read-Only Bit
    blockdev --setro "$dev"
    echo -e "${GREEN}[✓] Kernel block layer set to READ-ONLY on $dev.${NC}"

    # 2. Determine filesystem type
    local fstype
    fstype=$(blkid -o value -s TYPE "$dev" 2>/dev/null || true)
    local dev_name
    dev_name=$(basename "$dev")

    if [[ -z "$mount_target" ]]; then
        mount_target="/media/evidence/$dev_name"
    fi
    mkdir -p "$mount_target"

    echo -e "[*] Detected filesystem: ${BOLD}${fstype:-raw/unknown}${NC}"
    echo -e "[*] Mounting $dev -> $mount_target with zero-journal-write flags..."

    case "${fstype,,}" in
        ext3|ext4)
            # noload: Prevents the kernel from replaying dirty journal onto physical disk
            mount -t "$fstype" -o ro,noload,noatime,nodev,nosuid,noexec "$dev" "$mount_target"
            ;;
        xfs)
            # norecovery: Prevents log recovery and dirty journal replay
            mount -t xfs -o ro,norecovery,noatime,nodev,nosuid,noexec "$dev" "$mount_target"
            ;;
        btrfs)
            # rescue=nologreplay: Suppresses log tree replay on dirty btrfs
            mount -t btrfs -o ro,rescue=nologreplay,noatime,nodev,nosuid,noexec "$dev" "$mount_target"
            ;;
        ntfs)
            # ntfs3 with ro,norecover
            mount -t ntfs3 -o ro,norecover,noatime,nodev,nosuid,noexec "$dev" "$mount_target" 2>/dev/null || \
            mount -t ntfs-3g -o ro,noatime,nodev,nosuid,noexec "$dev" "$mount_target"
            ;;
        vfat|fat|msdos|exfat)
            mount -o ro,noatime,nodev,nosuid,noexec "$dev" "$mount_target"
            ;;
        apfs)
            if command -v apfs-fuse >/dev/null 2>&1; then
                apfs-fuse -o ro,allow_other "$dev" "$mount_target"
            else
                mount -t apfs -o ro,noatime "$dev" "$mount_target"
            fi
            ;;
        *)
            mount -o ro,noatime,nodev,nosuid,noexec "$dev" "$mount_target"
            ;;
    esac

    echo -e "${GREEN}${BOLD}[✓] Forensically mounted $dev at $mount_target (EVIDENCE SAFE: 0 writes / 0 journal replays)${NC}"
}

cmd_unblock() {
    local dev="$1"

    if [[ ! -b "$dev" ]]; then
        echo -e "${RED}[!] Error: $dev is not a valid block device.${NC}" >&2
        exit 1
    fi

    if is_system_device "$dev"; then
        echo -e "${RED}[⛔] ABORT: $dev belongs to the operating system! Unblocking refused.${NC}" >&2
        exit 1
    fi

    echo -e "${YELLOW}[!] WARNING: You are unblocking $dev for WRITE ACCESS.${NC}"
    echo -e "${YELLOW}    Only do this for DESTINATION media (where dfdisk saves .E01 / .raw images).${NC}"

    blockdev --setrw "$dev"

    # Also unblock parent disk if partition was given
    local pkname
    pkname=$(lsblk -no PKNAME "$dev" 2>/dev/null || true)
    if [[ -n "$pkname" && -b "/dev/$pkname" ]]; then
        blockdev --setrw "/dev/$pkname"
    fi

    echo -e "${RED}${BOLD}[✓] $dev is now UNBLOCKED (WRITABLE) for imaging with dfdisk.${NC}"
}

cmd_mount_target() {
    local dev="$1"
    local mount_target="${2:-}"

    if [[ ! -b "$dev" ]]; then
        echo -e "${RED}[!] Error: $dev is not a valid block device.${NC}" >&2
        exit 1
    fi

    if is_system_device "$dev"; then
        echo -e "${RED}[⛔] ABORT: $dev belongs to the operating system! Action blocked.${NC}" >&2
        exit 1
    fi

    # Unblock block layer
    blockdev --setrw "$dev"
    local pkname
    pkname=$(lsblk -no PKNAME "$dev" 2>/dev/null || true)
    if [[ -n "$pkname" && -b "/dev/$pkname" ]]; then
        blockdev --setrw "/dev/$pkname"
    fi

    local dev_name
    dev_name=$(basename "$dev")

    if [[ -z "$mount_target" ]]; then
        mount_target="/media/target/$dev_name"
    fi
    mkdir -p "$mount_target"

    echo -e "[*] Mounting $dev -> $mount_target as WRITEABLE TARGET..."
    mount -o rw,noatime "$dev" "$mount_target"

    local avail
    avail=$(df -h "$mount_target" | awk 'NR==2 {print $4}')
    echo -e "${RED}${BOLD}[✓] Mounted TARGET at $mount_target ($avail available for dfdisk output).${NC}"
}

cmd_umount() {
    local target="$1"
    echo -e "[*] Safely flushing and unmounting $target..."
    sync
    umount "$target"
    sync
    echo -e "${GREEN}[✓] Unmounted successfully.${NC}"
}

usage() {
    echo -e "${BOLD}df-mount${NC} - Forensic Storage & Target Management"
    echo "Usage:"
    echo "  df-mount status                     List storage devices, RO/RW state & forensic tags"
    echo "  df-mount evidence <dev> [target]    Mount partition forensically write-blocked (0 journal writes)"
    echo "  df-mount target <dev> [target]      Mount target drive writeable for dfdisk output"
    echo "  df-mount unblock <dev>              Unblock raw block device for cloning destination"
    echo "  df-mount umount <dev|path>          Safely flush and unmount"
    exit 1
}

case "${1:-status}" in
    status)
        cmd_status
        ;;
    evidence)
        [[ $# -ge 2 ]] || usage
        cmd_mount_evidence "$2" "${3:-}"
        ;;
    target)
        [[ $# -ge 2 ]] || usage
        cmd_mount_target "$2" "${3:-}"
        ;;
    unblock)
        [[ $# -ge 2 ]] || usage
        cmd_unblock "$2"
        ;;
    umount|unmount)
        [[ $# -ge 2 ]] || usage
        cmd_umount "$2"
        ;;
    *)
        usage
        ;;
esac
