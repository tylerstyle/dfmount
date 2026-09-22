# dfmount 🔒💾
> **Modern Forensic Storage Mounter, Write-Blocker & Target Ingestion Manager CLI/TUI for Digital Forensics and Incident Response.**

`dfmount` is a high-performance terminal utility designed for DFIR examiners, law enforcement investigators, and forensic field technicians. It provides safe, zero-journal-write mounting for evidence media, deliberate destination target unblocking for **[`dfdisk`](https://github.com/tylerstyle/dfdisk)** acquisition dumps, and active operating system drive protection with a dark **Ratatui TUI** dashboard.

---

## ⚡ Key Features

- **Asymmetric Evidence vs. Target Isolation**:
  - Automatically identifies block devices and marks them **Read-Only** (`blockdev --setro`).
  - Allows one-key unlocking of external destination drives (`blockdev --setrw`) to store forensic images.
- **Zero Journal Replay (Forensically Sound)**:
  - Mounts ext3/ext4 with `noload` to prevent kernel superblock / journal alteration.
  - Mounts XFS with `norecovery`.
  - Mounts Btrfs with `rescue=nologreplay`.
  - Mounts NTFS with `norecover`.
- **System Drive Guardrails**:
  - Automatically detects `/`, `/boot`, `/nix`, and active swap partitions to prevent accidental unmounting or modification.
- **Direct `dfdisk` Integration**:
  - Launch `dfdisk` directly from the dashboard with a single keypress (`d`).

---

## ⌨️ TUI Keyboard Shortcuts

- `↑` / `↓` / `k` / `j`: Navigate connected block devices
- `e`: Mount selected partition forensically **Read-Only** (zero journal replay)
- `t`: Mount selected partition as **Writeable Target** for `dfdisk` image output
- `u`: **Unblock** raw block device for direct physical drive cloning
- `x`: Safely flush buffers and **unmount**
- `d`: Launch **`dfdisk`** forensic imager
- `r`: Rescan storage media
- `q` / `Esc`: Quit

---

## 📦 CLI Usage

```bash
# Display connected storage matrix
sudo dfmount status

# Mount evidence partition read-only
sudo dfmount evidence /dev/sdb1

# Mount destination target drive writeable
sudo dfmount target /dev/sdc1

# Unblock raw disk for cloning target
sudo dfmount unblock /dev/sdc

# Safely unmount
sudo dfmount umount /media/evidence/sdb1
```

---

## 🔓 Target Unblocking Mechanics & Workflows

In a forensic live environment, attached block devices are write-blocked at the kernel level (`blockdev --setro`). When preparing a destination drive to receive forensic disk images (`.E01` or `.raw`) from `dfdisk`:

### The Kernel Rule: Parent Disk vs. Partition
In the Linux block layer, a partition device (e.g. `/dev/sdb1`) inherits read-only constraints from its parent disk (e.g. `/dev/sdb`). Specifically, `bdev_read_only(bdev)` evaluates:
```c
bdev->bd_read_only || get_disk_ro(bdev->bd_disk)
```
If the parent disk `/dev/sdb` is read-only, mounting `/dev/sdb1` read-write (`mount -o rw`) will **fail with EROFS** or be forced read-only. Similarly, if the partition itself has `ro=1`, writes will fail even if the parent disk is read-write. Both must be set to read-write.

### Automated Bi-Directional Unblocking in `dfmount`
To eliminate manual confusion and prevent mount failures, `dfmount` performs **bi-directional family unblocking**:
- **Selecting a Partition (`/dev/sdb1`)**: When mounting as target (`t`) or unblocking (`u`), `dfmount` executes `blockdev --setrw /dev/sdb1` **AND** resolves its parent disk (`/dev/sdb`), setting `blockdev --setrw /dev/sdb`.
- **Selecting a Whole Disk (`/dev/sdb`)**: When unblocking (`u`), `dfmount` executes `blockdev --setrw /dev/sdb` **AND** recursively unblocks all child partitions (`/dev/sdb1`, `/dev/sdb2`, etc.).

### Common Workflows & Special Cases
1. **Raw Whole-Disk Clone Target (`dfdisk clone /dev/sda /dev/sdb` or `dd`):**
   - Unblock the raw parent disk (`u` on `/dev/sdb`).
   - If partitions already exist on `/dev/sdb`, they must be unmounted before raw cloning.
2. **Filesystem Image Target (Saving `.E01` / `.raw` files into a filesystem):**
   - Select the destination partition (e.g. `/dev/sdc1`, formatted with exFAT, NTFS, ext4, or Btrfs) and press `t` (Mount Target).
   - `dfmount` automatically unblocks `/dev/sdc1` + `/dev/sdc` and mounts it at `/media/target/sdc1` with `rw,noatime`.
3. **Encrypted Destination Containers (LUKS / BitLocker):**
   - Unblock the underlying disk and partition first (`u` or `t` on `/dev/sdc1`).
   - Unlock the container: `sudo cryptsetup open /dev/sdc1 target_crypt`.
   - The resulting mapped device `/dev/mapper/target_crypt` is writable and can be mounted to `/media/target`.
4. **Operating System Protection (Hard Invariant):**
   - Live boot media labeled `DFNIX_LIVE`, `/`, `/boot`, `/nix`, and `/sysroot` are protected; `dfmount` strictly rejects any unblock or target mount requests targeting system devices.

---

## 📜 License
Distributed under the **MIT** or **Apache-2.0** License.
