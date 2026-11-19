# AGENTS.md — `dfmount`

`dfmount` is a forensic storage mounter, write-blocker, read-only encrypted/RAID/LVM/ZFS volume unlocker/assembler, and deliberate target-drive unblocker CLI/TUI in Rust (Ratatui + clap, MIT OR Apache-2.0).

## Multi-Repo & Dependency Context
- Part of the **df-suite** integrated into `~/git/dfnix`.
- Uses sibling Cargo path dependency `../dfcore` (`~/git/dfcore`). Keep `../dfcore` aligned with `flake.lock`.
- Push/release order when `dfcore` changes: `dfcore` -> `dfmount` -> `dfnix` (`nix flake update dfmount`).

## Build & Verification
```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
nix flake check
```

## Forensic Safety Invariants (NEVER Break)
- **Zero journal replay**: Evidence mounts MUST stay read-only (`blockdev --setro` verified before mount) with zero-replay options (`ext3`/`ext4`: `noload`; `xfs`: `norecovery`; `btrfs`: `rescue=nologreplay`; `ntfs`: read-only `ntfs3`/`ntfs-3g`).
- **Refuse ambiguous/unsafe devices**: Refuse devices in `/run/dfnix/protected.json`, active system mounts (`/`, `/boot`, `/nix`, `/iso`, `/sysroot`, active swap), and raw RAID/LVM/ZFS members during normal mount.
- **Read-only unlock & assembly**: `unlock` uses `cryptsetup open --readonly` (never log passphrases); `assemble` attaches via read-only loops (`losetup -r`).
- **Audit trail**: Log every mount, unblock, refusal, and unmount through `dfcore` (`/run/dfnix/audit.jsonl`).
- **Tests**: Must never mutate host block devices or mounts.

## Compact Instructions
When compacting, always preserve: `dfcore` compatibility, mount/unblock safety invariants touched, `cargo test` / `nix flake check` outcomes, and open TODOs.
