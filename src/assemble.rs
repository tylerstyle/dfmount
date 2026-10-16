//! Read-only reassembly of md RAID, LVM and ZFS from member images (or, as a
//! fallback, member disks), as in /etc/dfnix/playbooks/raid-lvm-zfs.md.
//!
//! Every member is attached with `losetup -r`: the loop device opens its
//! backing file or disk read-only, so nothing stacked on it can write to the
//! evidence, whatever md, LVM or ZFS try. On top of that each layer is
//! assembled read-only (`mdadm --readonly`, LVM `metadata_read_only` and
//! `read_only_volume_list`, `zpool import -o readonly=on`) and checked. What
//! was set up is recorded in /run/dfnix/assembled/<name>.json for
//! `dfmount disassemble`.

use anyhow::{bail, ensure, Context, Result};
use dfcore::audit::{Event, Outcome};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    devices::{resolve_non_system, FlatDevice},
    ops::set_ro_verified,
    sys::System,
};

const TOOL: &str = "dfmount";
const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const STATE_DIR: &str = "/run/dfnix/assembled";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Linux software RAID (also Synology/QNAP md layers, DDF, IMSM)
    Md,
    /// LVM volume group
    Lvm,
    /// ZFS pool
    Zfs,
}

/// What `assemble` set up, for `disassemble`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Assembly {
    pub name: String,
    pub kind: Kind,
    /// Members as given (image paths or devices)
    pub members: Vec<String>,
    /// Read-only loop devices, one per member
    pub loops: Vec<String>,
    /// md device, volume group or pool name
    pub assembled: String,
    /// Read-only block devices or mount root to examine
    pub results: Vec<String>,
}

fn out_ok(sys: &dyn System, program: &str, args: &[&str]) -> Result<String> {
    let out = sys
        .run(program, args)
        .with_context(|| format!("Failed to run {program}"))?;
    if !out.success() {
        bail!("{program} {} failed: {}", args.join(" "), out.stderr.trim());
    }
    Ok(out.stdout)
}

fn getro(sys: &dyn System, dev: &str) -> Result<bool> {
    Ok(out_ok(sys, "blockdev", &["--getro", dev])?.trim() == "1")
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

fn state_path(name: &str) -> String {
    format!("{STATE_DIR}/{name}.json")
}

/// Attach every member read-only. Block devices are checked against the
/// system and the registry and locked read-only first.
fn attach(
    sys: &dyn System,
    flat: &[FlatDevice],
    members: &[String],
    partscan: bool,
    loops: &mut Vec<String>,
) -> Result<()> {
    for member in members {
        // A symlink or relative path to a device is a device too
        if member.starts_with("/dev/") || sys.canonicalize(member).starts_with("/dev/") {
            let hits = resolve_non_system(sys, flat, member)?;
            set_ro_verified(sys, &hits[0].device.dev_path())?;
        } else {
            ensure!(sys.exists(member), "{member}: no such image file");
        }
        let mut args = vec!["-r", "-f", "--show"];
        if partscan {
            args.push("-P");
        }
        args.push(member);
        let lo = out_ok(sys, "losetup", &args)?.trim().to_string();
        ensure!(lo.starts_with("/dev/loop"), "losetup returned {lo:?}");
        loops.push(lo.clone());
        ensure!(getro(sys, &lo)?, "{lo} is not read-only");
    }
    Ok(())
}

fn detach(sys: &dyn System, loops: &[String]) {
    for lo in loops {
        let _ = sys.run("losetup", &["-d", lo]);
    }
}

fn lvm_config(vg: &str) -> String {
    format!(
        "global {{ metadata_read_only = 1 }} activation {{ read_only_volume_list = [ \"{vg}\" ] }}"
    )
}

/// Stop, deactivate or export what an assembly started (best effort).
fn take_down(sys: &dyn System, kind: Kind, assembled: &str, loops: &[String]) {
    match kind {
        Kind::Md => {
            let _ = sys.run("mdadm", &["--stop", assembled]);
        }
        Kind::Lvm => {
            let devices = loops.join(",");
            let config = lvm_config(assembled);
            let _ = sys.run(
                "vgchange",
                &["-an", "--devices", &devices, "--config", &config, assembled],
            );
        }
        Kind::Zfs => {
            let _ = sys.run("zpool", &["export", assembled]);
        }
    }
}

/// Run `check` on what was just started; on any failure take it down again.
fn checked<T>(
    sys: &dyn System,
    kind: Kind,
    assembled: &str,
    loops: &[String],
    check: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let result = check();
    if result.is_err() {
        take_down(sys, kind, assembled, loops);
    }
    result
}

fn assemble_md(sys: &dyn System, loops: &[String]) -> Result<(String, Vec<String>)> {
    let n = (100..1000)
        .find(|n| !sys.exists(&format!("/sys/block/md{n}")))
        .context("no free md device number")?;
    let md = format!("/dev/md{n}");
    let mut args = vec!["--assemble", "--readonly", md.as_str()];
    args.extend(loops.iter().map(String::as_str));
    out_ok(sys, "mdadm", &args)?;
    checked(sys, Kind::Md, &md, loops, || {
        let state = sys
            .read_file(&format!("/sys/block/md{n}/md/array_state"))
            .unwrap_or_default();
        ensure!(
            state.trim() == "readonly",
            "{md} is {:?}, not readonly; stopped it again",
            state.trim()
        );
        Ok((md.clone(), vec![md.clone()]))
    })
}

fn assemble_lvm(sys: &dyn System, loops: &[String]) -> Result<(String, Vec<String>)> {
    let devices = loops.join(",");
    let vgs: Vec<String> = out_ok(
        sys,
        "pvs",
        &["--devices", &devices, "--noheadings", "-o", "vg_name"],
    )?
    .lines()
    .map(|l| l.trim().to_string())
    .filter(|l| !l.is_empty())
    .collect::<std::collections::BTreeSet<_>>()
    .into_iter()
    .collect();
    let [vg] = vgs.as_slice() else {
        bail!(
            "the members hold {} volume groups ({}); give the members of one",
            vgs.len(),
            vgs.join(", ")
        );
    };
    let config = lvm_config(vg);
    out_ok(
        sys,
        "vgchange",
        &["-ay", "--devices", &devices, "--config", &config, vg],
    )?;
    checked(sys, Kind::Lvm, vg, loops, || {
        let lvs: Vec<String> = out_ok(
            sys,
            "lvs",
            &["--devices", &devices, "--noheadings", "-o", "lv_path", vg],
        )?
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
        for lv in &lvs {
            ensure!(
                getro(sys, lv)?,
                "{lv} is not read-only; deactivated {vg} again"
            );
        }
        Ok((vg.clone(), lvs))
    })
}

fn assemble_zfs(sys: &dyn System, loops: &[String]) -> Result<(String, Vec<String>)> {
    // The pool sits on the loop device or, for a whole-disk vdev, on its partitions
    let mut search = Vec::new();
    for lo in loops {
        search.push(lo.clone());
        for p in 1..=9 {
            let part = format!("{lo}p{p}");
            if sys.exists(&part) {
                search.push(part);
            }
        }
    }
    let mut list_args = vec!["import"];
    for d in &search {
        list_args.extend(["-d", d.as_str()]);
    }
    // `zpool import` without a pool name only lists; it exits 1 when there is none
    let listing = sys
        .run("zpool", &list_args)
        .context("Failed to run zpool")?;
    let pools: Vec<String> = listing
        .stdout
        .lines()
        .filter_map(|l| l.trim().strip_prefix("pool: "))
        .map(str::to_string)
        .collect();
    let [pool] = pools.as_slice() else {
        bail!(
            "the members hold {} ZFS pools ({}); give the members of one",
            pools.len(),
            pools.join(", ")
        );
    };
    let root = format!("/media/evidence/zfs_{pool}");
    let mut args = vec![
        "import",
        "-o",
        "readonly=on",
        "-o",
        "cachefile=none",
        "-N",
        "-R",
        root.as_str(),
        "-f",
    ];
    for d in &search {
        args.extend(["-d", d.as_str()]);
    }
    args.push(pool);
    out_ok(sys, "zpool", &args)?;
    checked(sys, Kind::Zfs, pool, loops, || {
        let ro = out_ok(
            sys,
            "zpool",
            &["get", "-H", "-o", "value", "readonly", pool],
        )?;
        ensure!(
            ro.trim() == "on",
            "pool {pool} is not imported read-only; exported it again"
        );
        Ok((pool.clone(), vec![root.clone()]))
    })
}

fn audit(
    sys: &dyn System,
    action: &str,
    details: Map<String, Value>,
    result: &Result<String>,
    refusal: bool,
) {
    let mut event = Event::new(TOOL, VERSION, action).result(result);
    if result.is_err() && refusal {
        event.outcome = Outcome::Refused;
    }
    event.details = details;
    sys.audit(event);
}

/// Assemble `kind` read-only from `members`.
pub fn assemble(
    sys: &dyn System,
    flat: &[FlatDevice],
    kind: Kind,
    members: &[String],
    name: Option<&str>,
) -> Result<String> {
    let mut details = Map::new();
    details.insert("kind".into(), serde_json::to_value(kind)?);
    details.insert("members".into(), members.into());
    let mut loops = Vec::new();
    let result = assemble_steps(sys, flat, kind, members, name, &mut loops, &mut details);
    if result.is_err() {
        detach(sys, &loops);
    }
    let refusal = !details.contains_key("attached");
    audit(sys, "raid_assemble", details, &result, refusal);
    result
}

fn assemble_steps(
    sys: &dyn System,
    flat: &[FlatDevice],
    kind: Kind,
    members: &[String],
    name: Option<&str>,
    loops: &mut Vec<String>,
    details: &mut Map<String, Value>,
) -> Result<String> {
    ensure!(!members.is_empty(), "no members given");
    if let Some(n) = name {
        ensure!(
            valid_name(n),
            "name {n:?}: use letters, digits, '_', '-' and '.'"
        );
        ensure!(
            !sys.exists(&state_path(n)),
            "an assembly named {n} exists; disassemble it first"
        );
    }
    attach(sys, flat, members, kind == Kind::Zfs, loops)?;
    details.insert("attached".into(), true.into());
    details.insert("loops".into(), loops.clone().into());
    let (assembled, results) = match kind {
        Kind::Md => assemble_md(sys, loops)?,
        Kind::Lvm => assemble_lvm(sys, loops)?,
        Kind::Zfs => assemble_zfs(sys, loops)?,
    };
    let name = name
        .map(str::to_string)
        .unwrap_or_else(|| assembled.trim_start_matches("/dev/").replace('/', "_"));
    checked(sys, kind, &assembled, loops, || {
        ensure!(
            !sys.exists(&state_path(&name)),
            "an assembly named {name} exists; disassemble it first"
        );
        Ok(())
    })?;
    let record = Assembly {
        name: name.clone(),
        kind,
        members: members.to_vec(),
        loops: loops.clone(),
        assembled: assembled.clone(),
        results: results.clone(),
    };
    details.insert("name".into(), name.clone().into());
    details.insert("assembled".into(), assembled.clone().into());
    details.insert("results".into(), results.clone().into());
    checked(sys, kind, &assembled, loops, || {
        sys.create_dir_all(STATE_DIR)?;
        sys.write_file(&state_path(&name), &serde_json::to_string_pretty(&record)?)?;
        Ok(())
    })?;
    let next = match kind {
        Kind::Zfs => format!(
            "mount datasets read-only with: zfs mount <dataset> (below {})",
            results[0]
        ),
        _ => format!(
            "mount with: dfmount evidence {}",
            results.first().map(String::as_str).unwrap_or("")
        ),
    };
    Ok(format!(
        "Assembled {assembled} read-only from {} as \"{name}\" ({}); {next}. Take it apart with: dfmount disassemble {name}",
        loops.join(", "),
        results.join(", ")
    ))
}

/// Take apart what `assemble` set up and detach its loop devices.
pub fn disassemble(sys: &dyn System, name: &str) -> Result<String> {
    let mut details = Map::new();
    details.insert("name".into(), name.into());
    let result = (|| -> Result<String> {
        ensure!(valid_name(name), "name {name:?}: not an assembly name");
        let record: Assembly = serde_json::from_str(
            &sys.read_file(&state_path(name))
                .with_context(|| format!("no assembly named {name}"))?,
        )?;
        details.insert("kind".into(), serde_json::to_value(record.kind)?);
        details.insert("assembled".into(), record.assembled.clone().into());
        match record.kind {
            Kind::Md => {
                out_ok(sys, "mdadm", &["--stop", &record.assembled])?;
            }
            Kind::Lvm => {
                let devices = record.loops.join(",");
                let config = lvm_config(&record.assembled);
                out_ok(
                    sys,
                    "vgchange",
                    &[
                        "-an",
                        "--devices",
                        &devices,
                        "--config",
                        &config,
                        &record.assembled,
                    ],
                )?;
            }
            Kind::Zfs => {
                out_ok(sys, "zpool", &["export", &record.assembled])?;
            }
        }
        for lo in &record.loops {
            out_ok(sys, "losetup", &["-d", lo])?;
        }
        sys.remove_file(&state_path(name))?;
        Ok(format!(
            "Took apart {} and detached {}",
            record.assembled,
            record.loops.join(", ")
        ))
    })();
    audit(sys, "raid_disassemble", details, &result, false);
    result
}
