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

## 📜 License
Distributed under the **MIT** or **Apache-2.0** License.
