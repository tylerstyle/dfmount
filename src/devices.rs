//! Device tree and system detection come from dfcore; this module adds lsblk
//! through the [`System`] seam and the guard every write path goes through.

use anyhow::{bail, Context, Result};

pub use dfcore::lsblk::{
    descendants, is_evidence_mount, is_mount_system, is_system_device, BlockDevice, DeviceIdentity,
    FlatDevice, LSBLK_COLUMNS,
};

use crate::sys::System;

pub fn parse_lsblk(json: &[u8]) -> Result<Vec<FlatDevice>> {
    dfcore::lsblk::parse(json)
}

pub fn fetch_devices(sys: &dyn System) -> Result<Vec<FlatDevice>> {
    let out = sys
        .run("lsblk", &["-J", "-o", LSBLK_COLUMNS])
        .context("Failed to run lsblk")?;
    if !out.success() {
        bail!("lsblk failed: {}", out.stderr.trim());
    }
    parse_lsblk(out.stdout.as_bytes())
}

/// All lsblk entries for `input` (after symlink resolution). Fails if the device
/// is unknown or any of its entries belongs to the running system, so the CLI
/// and the TUI share exactly the same protection rules.
pub fn resolve_non_system<'a>(
    sys: &dyn System,
    flat: &'a [FlatDevice],
    input: &str,
) -> Result<Vec<&'a FlatDevice>> {
    let want = sys.canonicalize(input);
    let hits: Vec<&FlatDevice> = flat
        .iter()
        .filter(|f| sys.canonicalize(&f.device.dev_path()) == want)
        .collect();
    if hits.is_empty() {
        bail!("{} is not a block device reported by lsblk", input);
    }
    if let Some(h) = hits.iter().find(|h| h.is_system) {
        bail!(
            "ABORT: {} belongs to the operating system!",
            h.device.dev_path()
        );
    }
    // The boot-time registry also knows system disks that are no longer mounted
    // or have re-enumerated under another name
    if let Some(registry) = sys.protected_registry()? {
        for h in &hits {
            if let Some(p) = registry.protecting(flat, &h.device.dev_path()) {
                bail!(
                    "ABORT: {} is protected by the dfnix registry ({:?} {}): {}",
                    h.device.dev_path(),
                    p.role,
                    p.identity
                        .serial
                        .as_deref()
                        .unwrap_or(&p.identity.kernel_name),
                    p.reasons.join("; ")
                );
            }
        }
    }
    Ok(hits)
}
