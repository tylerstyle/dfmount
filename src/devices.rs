use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::sys::System;

pub const LSBLK_COLUMNS: &str = "NAME,PATH,SIZE,RO,TYPE,FSTYPE,LABEL,MOUNTPOINTS,MODEL,SERIAL";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockDevice {
    pub name: String,
    pub path: Option<String>,
    pub size: Option<String>,
    pub ro: Option<bool>,
    #[serde(rename = "type")]
    pub dev_type: Option<String>,
    pub fstype: Option<String>,
    pub label: Option<String>,
    pub mountpoints: Option<Vec<Option<String>>>,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub children: Option<Vec<BlockDevice>>,
}

impl BlockDevice {
    pub fn dev_path(&self) -> String {
        self.path.clone().unwrap_or_else(|| format!("/dev/{}", self.name))
    }

    pub fn mounts(&self) -> impl Iterator<Item = &str> {
        self.mountpoints.iter().flatten().flatten().map(|s| s.as_str())
    }

    pub fn is_type(&self, t: &str) -> bool {
        self.dev_type.as_deref() == Some(t)
    }
}

#[derive(Debug, Deserialize)]
struct LsblkOutput {
    blockdevices: Vec<BlockDevice>,
}

#[derive(Debug, Clone)]
pub struct FlatDevice {
    pub device: BlockDevice,
    pub level: usize,
    pub is_system: bool,
    /// Paths of the enclosing devices, outermost (whole disk) first.
    /// lsblk lists a holder (dm, md) under every device it spans, so such a
    /// device appears once per parent, each time with a different chain.
    pub ancestors: Vec<String>,
}

pub fn is_mount_system(m: &str) -> bool {
    // Ignore desktop automounts under /run/media or /run/user
    if m.starts_with("/run/media/") || m.starts_with("/run/user/") {
        return false;
    }
    m == "/"
        || m.starts_with("/boot")
        || m.starts_with("/nix")
        || m.starts_with("/iso")
        || m.starts_with("/sysroot")
        || m.starts_with("/run")
        || m == "[SWAP]"
}

pub fn is_evidence_mount(m: &str) -> bool {
    m.starts_with("/media/evidence")
}

pub fn is_system_device(dev: &BlockDevice) -> bool {
    if dev.label.as_deref() == Some("DFNIX_LIVE") {
        return true;
    }
    if dev.mounts().any(is_mount_system) {
        return true;
    }
    dev.children.iter().flatten().any(is_system_device)
}

pub fn parse_lsblk(json: &[u8]) -> Result<Vec<FlatDevice>> {
    let parsed: LsblkOutput = serde_json::from_slice(json).context("Failed to parse lsblk JSON")?;
    let mut flat = Vec::new();

    fn recurse(dev: &BlockDevice, ancestors: &mut Vec<String>, parent_is_sys: bool, flat: &mut Vec<FlatDevice>) {
        let is_sys = parent_is_sys || is_system_device(dev);
        flat.push(FlatDevice {
            device: dev.clone(),
            level: ancestors.len(),
            is_system: is_sys,
            ancestors: ancestors.clone(),
        });
        ancestors.push(dev.dev_path());
        for c in dev.children.iter().flatten() {
            recurse(c, ancestors, is_sys, flat);
        }
        ancestors.pop();
    }

    for dev in &parsed.blockdevices {
        recurse(dev, &mut Vec::new(), false, &mut flat);
    }
    Ok(flat)
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
pub fn resolve_non_system<'a>(sys: &dyn System, flat: &'a [FlatDevice], input: &str) -> Result<Vec<&'a FlatDevice>> {
    let want = sys.canonicalize(input);
    let hits: Vec<&FlatDevice> = flat
        .iter()
        .filter(|f| sys.canonicalize(&f.device.dev_path()) == want)
        .collect();
    if hits.is_empty() {
        bail!("{} is not a block device reported by lsblk", input);
    }
    if let Some(h) = hits.iter().find(|h| h.is_system) {
        bail!("ABORT: {} belongs to the operating system!", h.device.dev_path());
    }
    Ok(hits)
}

/// Every entry nested anywhere below `path`.
pub fn descendants<'a>(flat: &'a [FlatDevice], path: &str) -> impl Iterator<Item = &'a FlatDevice> + 'a {
    let path = path.to_string();
    flat.iter().filter(move |f| f.ancestors.contains(&path))
}
