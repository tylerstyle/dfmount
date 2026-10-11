use anyhow::{bail, Context, Result};
use std::path::Path;

use crate::{
    devices::{descendants, is_evidence_mount, resolve_non_system, FlatDevice},
    probe::{mount_plan, parse_blkid},
    sys::System,
};

fn dev_basename(dev: &str, fallback: &str) -> String {
    Path::new(dev)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| fallback.to_string())
}

fn blockdev_getro(sys: &dyn System, dev: &str) -> Result<bool> {
    let out = sys.run("blockdev", &["--getro", dev]).context("Failed to run blockdev --getro")?;
    if !out.success() {
        bail!("blockdev --getro {} failed: {}", dev, out.stderr.trim());
    }
    match out.stdout.trim() {
        "1" => Ok(true),
        "0" => Ok(false),
        other => bail!("blockdev --getro {} returned unexpected output '{}'", dev, other),
    }
}

/// Set the kernel read-only flag and read it back. Any failure is fatal.
pub fn set_ro_verified(sys: &dyn System, dev: &str) -> Result<()> {
    let out = sys.run("blockdev", &["--setro", dev]).context("Failed to run blockdev --setro")?;
    if !out.success() {
        bail!("blockdev --setro {} failed ({}); refusing to continue", dev, out.stderr.trim());
    }
    if !blockdev_getro(sys, dev)? {
        bail!("{} is still writable after blockdev --setro; refusing to continue", dev);
    }
    Ok(())
}

fn set_rw_verified(sys: &dyn System, dev: &str) -> Result<()> {
    let out = sys.run("blockdev", &["--setrw", dev]).context("Failed to run blockdev --setrw")?;
    if !out.success() {
        bail!("blockdev --setrw {} failed: {}", dev, out.stderr.trim());
    }
    if blockdev_getro(sys, dev)? {
        bail!("{} is still read-only after blockdev --setrw", dev);
    }
    Ok(())
}

/// Mount a device read-only without journal or log replay.
pub fn mount_evidence(sys: &dyn System, flat: &[FlatDevice], device: &str, target: Option<&str>) -> Result<String> {
    let hits = resolve_non_system(sys, flat, device)?;
    let dev = hits[0].device.dev_path();

    // 1. Kernel read-only flag, verified, before anything reads the device
    set_ro_verified(sys, &dev)?;

    // 2. Low-level probe of the on-disk signature
    let probe = sys.run("blkid", &["-p", "-o", "export", &dev]).context("Failed to run blkid")?;
    let fstype = parse_blkid(&dev, probe.code, &probe.stdout)?;
    let plan = mount_plan(&fstype)?;

    let mnt_target = target
        .map(str::to_string)
        .unwrap_or_else(|| format!("/media/evidence/{}", dev_basename(&dev, "evidence")));
    sys.create_dir_all(&mnt_target)
        .with_context(|| format!("Failed to create mountpoint {}", mnt_target))?;

    // 3. Only the replay-safe attempts for this filesystem; no generic fallback
    let mut errors = Vec::new();
    for attempt in &plan {
        let out = sys
            .run("mount", &["-t", attempt.fstype, "-o", &attempt.options, &dev, &mnt_target])
            .context("Failed to run mount")?;
        if out.success() {
            return Ok(format!(
                "Forensically mounted {} ({}) at {} [{}]",
                dev, attempt.fstype, mnt_target, attempt.options
            ));
        }
        errors.push(format!("{}: {}", attempt.fstype, out.stderr.trim()));
    }
    bail!("Evidence mount of {} failed: {}", dev, errors.join("; "))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnblockMode {
    /// Make a filesystem writable for mounting as image destination
    Target,
    /// Make a device writable for raw cloning; nothing on it may be mounted
    Raw,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnblockPlan {
    pub device: String,
    /// Kernel name the examiner has to type to confirm
    pub confirm_name: String,
    /// Nodes that will be made writable, outermost first
    pub writable: Vec<String>,
    /// Partitions that keep their own read-only flag but sit on a disk node
    /// that becomes writable, so raw writes to that disk can still reach them
    pub exposed: Vec<String>,
}

impl UnblockPlan {
    pub fn confirms(&self, typed: &str) -> bool {
        typed.trim() == self.confirm_name
    }

    pub fn summary(&self) -> String {
        let mut s = format!("Will make WRITABLE: {}", self.writable.join(", "));
        if !self.exposed.is_empty() {
            s.push_str(&format!(
                ". Still read-only but reachable through the writable disk: {}",
                self.exposed.join(", ")
            ));
        }
        s
    }
}

/// Work out which nodes a target/unblock would make writable, and refuse when
/// that would expose system or evidence media.
pub fn plan_unblock(sys: &dyn System, flat: &[FlatDevice], device: &str, mode: UnblockMode) -> Result<UnblockPlan> {
    let hits = resolve_non_system(sys, flat, device)?;
    let dev = hits[0].device.dev_path();

    // The device and everything stacked on it
    let subtree: Vec<&FlatDevice> = hits.iter().copied().chain(descendants(flat, &dev)).collect();
    for d in &subtree {
        for m in d.device.mounts() {
            if is_evidence_mount(m) {
                bail!("ABORT: {} is mounted as evidence at {}", d.device.dev_path(), m);
            }
            if mode == UnblockMode::Raw {
                bail!("{} is mounted at {}; unmount it before unblocking for raw writes", d.device.dev_path(), m);
            }
        }
    }

    // Linux treats a partition as read-only if its disk is, so every enclosing
    // device has to become writable as well (bdev_read_only)
    let mut writable: Vec<String> = Vec::new();
    let push = |p: &str, v: &mut Vec<String>| {
        if !v.iter().any(|x| x == p) {
            v.push(p.to_string());
        }
    };
    for h in &hits {
        for a in &h.ancestors {
            push(a, &mut writable);
        }
    }
    push(&dev, &mut writable);
    for d in descendants(flat, &dev).filter(|d| d.device.is_type("part")) {
        push(&d.device.dev_path(), &mut writable);
    }

    // Everything else on the whole disks that become writable
    let mut roots: Vec<String> = Vec::new();
    for h in &hits {
        push(h.ancestors.first().unwrap_or(&dev), &mut roots);
    }
    let in_subtree = |p: &str| subtree.iter().any(|s| s.device.dev_path() == p);
    let mut exposed = Vec::new();
    for root in &roots {
        for d in flat.iter().filter(|f| f.device.dev_path() == *root || f.ancestors.contains(root)) {
            let path = d.device.dev_path();
            if in_subtree(&path) {
                continue;
            }
            if let Some(m) = d.device.mounts().find(|m| is_evidence_mount(m)) {
                bail!(
                    "ABORT: {} also holds evidence {} mounted at {}; making {} writable would expose it",
                    root,
                    path,
                    m,
                    root
                );
            }
            if d.device.is_type("part") && !writable.contains(&path) {
                push(&path, &mut exposed);
            }
        }
    }

    Ok(UnblockPlan {
        device: dev,
        confirm_name: hits[0].device.name.clone(),
        writable,
        exposed,
    })
}

/// Clear the read-only flag on every node in the plan. If one fails, the nodes
/// already unblocked are set read-only again.
pub fn apply_unblock(sys: &dyn System, plan: &UnblockPlan) -> Result<()> {
    for (i, node) in plan.writable.iter().enumerate() {
        if let Err(e) = set_rw_verified(sys, node) {
            for done in plan.writable[..=i].iter().rev() {
                let _ = sys.run("blockdev", &["--setro", done]);
            }
            return Err(e.context(format!("Unblocking {} aborted; nodes set read-only again", plan.device)));
        }
    }
    Ok(())
}

pub fn unblock_device(sys: &dyn System, plan: &UnblockPlan) -> Result<String> {
    apply_unblock(sys, plan)?;
    Ok(format!("UNBLOCKED (WRITABLE): {}", plan.writable.join(", ")))
}

pub fn mount_target(sys: &dyn System, plan: &UnblockPlan, target: Option<&str>) -> Result<String> {
    apply_unblock(sys, plan)?;

    let mnt_target = target
        .map(str::to_string)
        .unwrap_or_else(|| format!("/media/target/{}", dev_basename(&plan.device, "target")));
    sys.create_dir_all(&mnt_target)
        .with_context(|| format!("Failed to create mountpoint {}", mnt_target))?;

    let out = sys
        .run("mount", &["-o", "rw,noatime", &plan.device, &mnt_target])
        .context("Failed to run mount")?;
    if out.success() {
        Ok(format!("Mounted TARGET {} at {} for dfdisk output", plan.device, mnt_target))
    } else {
        bail!("Target mount of {} failed: {}", plan.device, out.stderr.trim())
    }
}

pub fn unmount_device(sys: &dyn System, target: &str) -> Result<String> {
    let _ = sys.run("sync", &[]);
    let out = sys.run("umount", &[target])?;
    let _ = sys.run("sync", &[]);
    if out.success() {
        Ok(format!("Safely flushed and unmounted {}", target))
    } else {
        bail!("Failed to unmount {}: {}", target, out.stderr.trim())
    }
}
