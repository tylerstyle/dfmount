//! Safety rules of dfmount against a recorded lsblk tree, with every external
//! command answered by a simulated host that tracks kernel read-only flags.

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    io,
};

use dfcore::{
    audit::{Event, Outcome},
    protected::Registry,
};
use dfmount::{
    assemble::{assemble, disassemble, Kind},
    devices::{is_mount_system, parse_lsblk, FlatDevice},
    ops::{
        apply_unblock, lock, mount_evidence, mount_target, plan_unblock, record_unconfirmed,
        unblock_device, unlock, unmount_device, CryptKind, UnblockMode,
    },
    sys::{CmdOutput, System},
};

const LAB: &str = include_str!("fixtures/lsblk-lab.json");

fn lab() -> Vec<FlatDevice> {
    parse_lsblk(LAB.as_bytes()).expect("fixture parses")
}

#[derive(Default)]
struct FakeHost {
    /// Exact command lines with a canned answer
    responses: HashMap<String, CmdOutput>,
    /// Command lines that exit 1
    failing: HashSet<String>,
    /// Kernel read-only flag per device, as blockdev --setro/--setrw leave it
    ro: RefCell<HashMap<String, bool>>,
    aliases: HashMap<String, String>,
    calls: RefCell<Vec<String>>,
    registry: Option<Registry>,
    events: RefCell<Vec<Event>>,
    /// Exit code of interactive commands (cryptsetup with a prompt); None = 0
    interactive_exit: Option<i32>,
    /// Files and paths that exist on the simulated host
    files: RefCell<HashMap<String, String>>,
}

impl FakeHost {
    fn new() -> Self {
        Self::default()
    }

    fn respond(mut self, cmd: &str, code: i32, stdout: &str) -> Self {
        self.responses.insert(
            cmd.to_string(),
            CmdOutput {
                code: Some(code),
                stdout: stdout.to_string(),
                stderr: String::new(),
            },
        );
        self
    }

    fn fail(mut self, cmd: &str) -> Self {
        self.failing.insert(cmd.to_string());
        self
    }

    fn file(self, path: &str, content: &str) -> Self {
        self.files
            .borrow_mut()
            .insert(path.to_string(), content.to_string());
        self
    }

    fn interactive_exit(mut self, code: i32) -> Self {
        self.interactive_exit = Some(code);
        self
    }

    /// A device whose kernel read-only flag reads 0
    fn writable(self, dev: &str) -> Self {
        self.ro.borrow_mut().insert(dev.to_string(), false);
        self
    }

    fn alias(mut self, link: &str, target: &str) -> Self {
        self.aliases.insert(link.to_string(), target.to_string());
        self
    }

    fn with_registry(mut self, registry: Registry) -> Self {
        self.registry = Some(registry);
        self
    }

    fn events(&self) -> Vec<(String, Outcome)> {
        self.events
            .borrow()
            .iter()
            .map(|e| (e.action.clone(), e.outcome))
            .collect()
    }

    fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }

    fn mounts(&self) -> Vec<String> {
        self.calls()
            .into_iter()
            .filter(|c| c.starts_with("mount "))
            .collect()
    }
}

impl System for FakeHost {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<CmdOutput> {
        let line = std::iter::once(program)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        self.calls.borrow_mut().push(line.clone());
        if self.failing.contains(&line) {
            return Ok(CmdOutput {
                code: Some(1),
                stdout: String::new(),
                stderr: "simulated failure".into(),
            });
        }
        if let Some(r) = self.responses.get(&line) {
            return Ok(r.clone());
        }
        let ok = |stdout: &str| CmdOutput {
            code: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        };
        Ok(match (program, args) {
            ("blockdev", ["--setro", dev]) => {
                self.ro.borrow_mut().insert(dev.to_string(), true);
                ok("")
            }
            ("blockdev", ["--setrw", dev]) => {
                self.ro.borrow_mut().insert(dev.to_string(), false);
                ok("")
            }
            ("blockdev", ["--getro", dev]) => {
                let ro = self.ro.borrow().get(*dev).copied().unwrap_or(true);
                ok(if ro { "1\n" } else { "0\n" })
            }
            _ => ok(""),
        })
    }

    fn run_interactive(&self, program: &str, args: &[&str]) -> io::Result<Option<i32>> {
        let line = std::iter::once(program)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        self.calls.borrow_mut().push(format!("tty {line}"));
        Ok(Some(self.interactive_exit.unwrap_or(0)))
    }

    fn canonicalize(&self, path: &str) -> String {
        self.aliases
            .get(path)
            .cloned()
            .unwrap_or_else(|| path.to_string())
    }

    fn create_dir_all(&self, _path: &str) -> io::Result<()> {
        Ok(())
    }

    fn read_file(&self, path: &str) -> io::Result<String> {
        self.files
            .borrow()
            .get(path)
            .cloned()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }

    fn write_file(&self, path: &str, content: &str) -> io::Result<()> {
        self.files
            .borrow_mut()
            .insert(path.to_string(), content.to_string());
        Ok(())
    }

    fn remove_file(&self, path: &str) -> io::Result<()> {
        self.files
            .borrow_mut()
            .remove(path)
            .map(|_| ())
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }

    fn exists(&self, path: &str) -> bool {
        self.files.borrow().contains_key(path)
    }

    fn protected_registry(&self) -> anyhow::Result<Option<Registry>> {
        Ok(self.registry.clone())
    }

    fn audit(&self, event: Event) {
        self.events.borrow_mut().push(event);
    }
}

fn err_of<T: std::fmt::Debug>(r: anyhow::Result<T>) -> String {
    format!("{:#}", r.expect_err("operation must be refused"))
}

// ---------------------------------------------------------------------------
// Device tree parsing and system detection
// ---------------------------------------------------------------------------

#[test]
fn system_mountpoints() {
    for m in [
        "/",
        "/boot",
        "/boot/efi",
        "/nix/store",
        "/iso",
        "/sysroot",
        "/run/initramfs",
        "[SWAP]",
    ] {
        assert!(is_mount_system(m), "{m}");
    }
    for m in [
        "/run/media/nixos/STICK",
        "/run/user/1000/gvfs",
        "/media/evidence/sdb1",
        "/media/target/sdh1",
        "/mnt",
    ] {
        assert!(!is_mount_system(m), "{m}");
    }
}

#[test]
fn whole_system_disk_and_live_media_are_protected() {
    let flat = lab();
    let sys_names: Vec<_> = flat
        .iter()
        .filter(|f| f.is_system)
        .map(|f| f.device.name.as_str())
        .collect();
    assert_eq!(sys_names, ["nvme0n1", "nvme0n1p1", "nvme0n1p2", "sr0"]);
}

#[test]
fn tree_levels_and_ancestors() {
    let flat = lab();
    let luks = flat.iter().find(|f| f.device.name == "luks-tgt").unwrap();
    assert_eq!(luks.level, 2);
    assert_eq!(luks.ancestors, ["/dev/sdc", "/dev/sdc2"]);
    // A RAID array shows up once under each member
    let md: Vec<_> = flat
        .iter()
        .filter(|f| f.device.name == "md0")
        .map(|f| f.ancestors.clone())
        .collect();
    assert_eq!(
        md,
        [vec!["/dev/sdf", "/dev/sdf1"], vec!["/dev/sdg", "/dev/sdg1"]]
    );
}

// ---------------------------------------------------------------------------
// CLI and TUI share the same system guard
// ---------------------------------------------------------------------------

#[test]
fn system_devices_are_refused_by_every_write_path() {
    let flat = lab();
    for dev in [
        "/dev/nvme0n1",
        "/dev/nvme0n1p1",
        "/dev/nvme0n1p2",
        "/dev/sr0",
    ] {
        let host = FakeHost::new();
        assert!(
            err_of(mount_evidence(&host, &flat, dev, None)).contains("operating system"),
            "{dev}"
        );
        assert!(
            err_of(plan_unblock(&host, &flat, dev, UnblockMode::Target))
                .contains("operating system"),
            "{dev}"
        );
        assert!(
            err_of(plan_unblock(&host, &flat, dev, UnblockMode::Raw)).contains("operating system"),
            "{dev}"
        );
        assert!(host.calls().is_empty(), "{dev}: {:?}", host.calls());
    }
}

#[test]
fn system_guard_follows_symlinks() {
    let flat = lab();
    let host = FakeHost::new().alias(
        "/dev/disk/by-id/nvme-Samsung_SSD_990-part2",
        "/dev/nvme0n1p2",
    );
    let err = err_of(plan_unblock(
        &host,
        &flat,
        "/dev/disk/by-id/nvme-Samsung_SSD_990-part2",
        UnblockMode::Raw,
    ));
    assert!(err.contains("operating system"), "{err}");
}

#[test]
fn desktop_automount_is_not_treated_as_system() {
    let plan = plan_unblock(&FakeHost::new(), &lab(), "/dev/sde1", UnblockMode::Target).unwrap();
    assert_eq!(plan.writable, ["/dev/sde", "/dev/sde1"]);
}

#[test]
fn unknown_device_is_refused() {
    let err = err_of(plan_unblock(
        &FakeHost::new(),
        &lab(),
        "/dev/sdz",
        UnblockMode::Raw,
    ));
    assert!(err.contains("not a block device"), "{err}");
}

// ---------------------------------------------------------------------------
// Evidence mounts
// ---------------------------------------------------------------------------

#[test]
fn evidence_mount_sequence_for_ext4() {
    let host = FakeHost::new().respond(
        "blkid -p -o export /dev/sdb2",
        0,
        "TYPE=ext4\nUSAGE=filesystem\n",
    );
    let msg = mount_evidence(&host, &lab(), "/dev/sdb2", None).unwrap();
    assert!(msg.contains("/media/evidence/sdb2"), "{msg}");
    assert_eq!(
        host.calls(),
        [
            "blockdev --setro /dev/sdb2",
            "blockdev --getro /dev/sdb2",
            "blkid -p -o export /dev/sdb2",
            "mount -t ext4 -o ro,noatime,nodev,nosuid,noexec,noload /dev/sdb2 /media/evidence/sdb2",
        ]
    );
}

#[test]
fn failed_setro_aborts_before_probe_or_mount() {
    let host = FakeHost::new().fail("blockdev --setro /dev/sdb2");
    let err = err_of(mount_evidence(&host, &lab(), "/dev/sdb2", None));
    assert!(err.contains("--setro"), "{err}");
    assert_eq!(host.calls(), ["blockdev --setro /dev/sdb2"]);
}

#[test]
fn setro_that_does_not_stick_aborts() {
    let host = FakeHost::new().respond("blockdev --getro /dev/sdb2", 0, "0\n");
    let err = err_of(mount_evidence(&host, &lab(), "/dev/sdb2", None));
    assert!(err.contains("still writable"), "{err}");
    assert!(host.mounts().is_empty());
}

#[test]
fn unreadable_getro_aborts() {
    let host = FakeHost::new().fail("blockdev --getro /dev/sdb2");
    assert!(mount_evidence(&host, &lab(), "/dev/sdb2", None).is_err());
    assert!(host.mounts().is_empty());
}

#[test]
fn ambiguous_or_missing_signature_is_not_mounted() {
    for (code, stdout) in [
        (8, ""),
        (2, ""),
        (0, "TYPE=apfs\nUSAGE=filesystem\n"),
        (0, "TYPE=crypto_LUKS\nUSAGE=crypto\n"),
    ] {
        let host = FakeHost::new().respond("blkid -p -o export /dev/sdb2", code, stdout);
        assert!(
            mount_evidence(&host, &lab(), "/dev/sdb2", None).is_err(),
            "{code} {stdout}"
        );
        assert!(
            host.mounts().is_empty(),
            "{code} {stdout}: {:?}",
            host.mounts()
        );
        // The device was still locked first
        assert_eq!(host.calls()[0], "blockdev --setro /dev/sdb2");
    }
}

#[test]
fn ntfs_falls_back_to_ntfs3g_never_to_untyped_mount() {
    let host = FakeHost::new()
        .respond(
            "blkid -p -o export /dev/sdb2",
            0,
            "TYPE=ntfs\nUSAGE=filesystem\n",
        )
        .fail("mount -t ntfs3 -o ro,noatime,nodev,nosuid,noexec /dev/sdb2 /media/evidence/sdb2");
    let msg = mount_evidence(&host, &lab(), "/dev/sdb2", None).unwrap();
    assert!(msg.contains("ntfs-3g"), "{msg}");
    assert_eq!(
        host.mounts(),
        [
            "mount -t ntfs3 -o ro,noatime,nodev,nosuid,noexec /dev/sdb2 /media/evidence/sdb2",
            "mount -t ntfs-3g -o ro,noatime,nodev,nosuid,noexec /dev/sdb2 /media/evidence/sdb2",
        ]
    );
}

#[test]
fn ntfs_with_both_drivers_failing_reports_both() {
    let host = FakeHost::new()
        .respond("blkid -p -o export /dev/sdb2", 0, "TYPE=ntfs\n")
        .fail("mount -t ntfs3 -o ro,noatime,nodev,nosuid,noexec /dev/sdb2 /media/evidence/sdb2")
        .fail("mount -t ntfs-3g -o ro,noatime,nodev,nosuid,noexec /dev/sdb2 /media/evidence/sdb2");
    let err = err_of(mount_evidence(&host, &lab(), "/dev/sdb2", None));
    assert!(err.contains("ntfs3") && err.contains("ntfs-3g"), "{err}");
    assert_eq!(host.mounts().len(), 2);
}

#[test]
fn evidence_mount_honours_custom_mountpoint() {
    let host = FakeHost::new().respond("blkid -p -o export /dev/sdb2", 0, "TYPE=xfs\n");
    mount_evidence(&host, &lab(), "/dev/sdb2", Some("/mnt/case42")).unwrap();
    assert_eq!(
        host.mounts(),
        ["mount -t xfs -o ro,noatime,nodev,nosuid,noexec,norecovery /dev/sdb2 /mnt/case42"]
    );
}

// ---------------------------------------------------------------------------
// Target isolation and unblock plans
// ---------------------------------------------------------------------------

#[test]
fn target_partition_unblocks_only_its_own_chain() {
    let plan = plan_unblock(&FakeHost::new(), &lab(), "/dev/sdc1", UnblockMode::Target).unwrap();
    assert_eq!(plan.confirm_name, "sdc1");
    assert_eq!(plan.writable, ["/dev/sdc", "/dev/sdc1"]);
    assert_eq!(plan.exposed, ["/dev/sdc2"]);
    assert!(plan.summary().contains("/dev/sdc2"));
}

#[test]
fn raw_unblock_of_disk_covers_partitions_but_not_holders() {
    let plan = plan_unblock(&FakeHost::new(), &lab(), "/dev/sdc", UnblockMode::Raw).unwrap();
    assert_eq!(plan.confirm_name, "sdc");
    assert_eq!(plan.writable, ["/dev/sdc", "/dev/sdc1", "/dev/sdc2"]);
    assert!(plan.exposed.is_empty());
}

#[test]
fn blank_disk_unblock() {
    let plan = plan_unblock(&FakeHost::new(), &lab(), "/dev/sdd", UnblockMode::Raw).unwrap();
    assert_eq!(plan.writable, ["/dev/sdd"]);
}

#[test]
fn partition_next_to_mounted_evidence_is_refused() {
    let err = err_of(plan_unblock(
        &FakeHost::new(),
        &lab(),
        "/dev/sdb2",
        UnblockMode::Target,
    ));
    assert!(err.contains("also holds evidence /dev/sdb1"), "{err}");
}

#[test]
fn disk_hosting_evidence_is_refused() {
    for mode in [UnblockMode::Target, UnblockMode::Raw] {
        let err = err_of(plan_unblock(&FakeHost::new(), &lab(), "/dev/sdb", mode));
        assert!(err.contains("evidence"), "{err}");
    }
}

#[test]
fn evidence_mount_itself_cannot_become_target() {
    let err = err_of(plan_unblock(
        &FakeHost::new(),
        &lab(),
        "/dev/sdb1",
        UnblockMode::Target,
    ));
    assert!(err.contains("mounted as evidence"), "{err}");
}

#[test]
fn raw_unblock_requires_everything_unmounted() {
    let err = err_of(plan_unblock(
        &FakeHost::new(),
        &lab(),
        "/dev/sdh",
        UnblockMode::Raw,
    ));
    assert!(err.contains("unmount"), "{err}");
    // A second filesystem next to a mounted target is fine
    let plan = plan_unblock(&FakeHost::new(), &lab(), "/dev/sdh2", UnblockMode::Target).unwrap();
    assert_eq!(plan.writable, ["/dev/sdh", "/dev/sdh2"]);
}

#[test]
fn mapped_device_resolves_through_alias_and_unblocks_backing_chain() {
    let host = FakeHost::new()
        .alias("/dev/mapper/luks-tgt", "/dev/dm-0")
        .alias("/dev/dm-0", "/dev/dm-0");
    let plan = plan_unblock(&host, &lab(), "/dev/dm-0", UnblockMode::Target).unwrap();
    assert_eq!(plan.confirm_name, "luks-tgt");
    assert_eq!(
        plan.writable,
        ["/dev/sdc", "/dev/sdc2", "/dev/mapper/luks-tgt"]
    );
    assert_eq!(plan.exposed, ["/dev/sdc1"]);
}

#[test]
fn array_spanning_disks_lists_every_member() {
    let plan = plan_unblock(&FakeHost::new(), &lab(), "/dev/md0", UnblockMode::Target).unwrap();
    assert_eq!(
        plan.writable,
        ["/dev/sdf", "/dev/sdf1", "/dev/sdg", "/dev/sdg1", "/dev/md0"]
    );
}

#[test]
fn typed_confirmation_must_match_exactly() {
    let plan = plan_unblock(&FakeHost::new(), &lab(), "/dev/sdc1", UnblockMode::Target).unwrap();
    assert!(plan.confirms("sdc1"));
    assert!(plan.confirms("  sdc1\n"));
    for wrong in ["", "sdc", "SDC1", "/dev/sdc1", "sdc12", "y", "yes"] {
        assert!(!plan.confirms(wrong), "{wrong:?}");
    }
}

// ---------------------------------------------------------------------------
// Applying unblocks
// ---------------------------------------------------------------------------

#[test]
fn unblock_sets_and_verifies_every_node() {
    let host = FakeHost::new();
    let plan = plan_unblock(&host, &lab(), "/dev/sdc", UnblockMode::Raw).unwrap();
    unblock_device(&host, &lab(), &plan).unwrap();
    for node in &plan.writable {
        assert_eq!(host.ro.borrow().get(node), Some(&false), "{node}");
    }
    assert!(host
        .calls()
        .contains(&"blockdev --getro /dev/sdc2".to_string()));
}

#[test]
fn failed_setrw_rolls_back_to_read_only() {
    let host = FakeHost::new().fail("blockdev --setrw /dev/sdc1");
    let plan = plan_unblock(&host, &lab(), "/dev/sdc", UnblockMode::Raw).unwrap();
    let err = err_of(apply_unblock(&host, &plan));
    assert!(err.contains("read-only again"), "{err}");
    for node in ["/dev/sdc", "/dev/sdc1"] {
        assert_eq!(host.ro.borrow().get(node), Some(&true), "{node}");
    }
    assert!(!host
        .calls()
        .iter()
        .any(|c| c == "blockdev --setrw /dev/sdc2"));
}

#[test]
fn target_mount_unblocks_then_mounts_rw() {
    let host = FakeHost::new();
    let plan = plan_unblock(&host, &lab(), "/dev/sdc1", UnblockMode::Target).unwrap();
    mount_target(&host, &lab(), &plan, None).unwrap();
    assert_eq!(
        host.mounts(),
        ["mount -o rw,noatime /dev/sdc1 /media/target/sdc1"]
    );
    let calls = host.calls();
    let mount_at = calls.iter().position(|c| c.starts_with("mount ")).unwrap();
    assert!(calls[..mount_at].contains(&"blockdev --setrw /dev/sdc".to_string()));
    assert!(calls[..mount_at].contains(&"blockdev --setrw /dev/sdc1".to_string()));
    assert!(!calls.iter().any(|c| c.contains("/dev/sdc2")));
}

#[test]
fn target_is_not_mounted_when_unblock_fails() {
    let host = FakeHost::new().respond("blockdev --getro /dev/sdc1", 0, "1\n");
    let plan = plan_unblock(&host, &lab(), "/dev/sdc1", UnblockMode::Target).unwrap();
    assert!(mount_target(&host, &lab(), &plan, None).is_err());
    assert!(host.mounts().is_empty());
}

// ---------------------------------------------------------------------------
// Protected-device registry (dfcore) and audit trail
// ---------------------------------------------------------------------------

/// The lab tree after the system disk was unmounted (e.g. copy-to-RAM boot):
/// nothing on it looks like the system any more.
fn lab_unmounted() -> Vec<FlatDevice> {
    let json = include_str!("fixtures/lsblk-lab.json")
        .replace("\"mountpoints\":[\"/boot\"]", "\"mountpoints\":[null]")
        .replace(
            "\"mountpoints\":[\"/nix/store\", \"/\"]",
            "\"mountpoints\":[null]",
        )
        .replace("\"label\":\"DFNIX_LIVE\"", "\"label\":null");
    parse_lsblk(json.as_bytes()).unwrap()
}

#[test]
fn registry_protects_a_system_disk_that_no_longer_looks_like_one() {
    let registry = Registry::build(&lab());
    let flat = lab_unmounted();
    assert!(flat.iter().all(|f| !f.is_system));
    // Without the registry the old system disk would be fair game
    assert!(plan_unblock(
        &FakeHost::new(),
        &flat,
        "/dev/nvme0n1p2",
        UnblockMode::Target
    )
    .is_ok());

    let host = FakeHost::new().with_registry(registry);
    for dev in ["/dev/nvme0n1", "/dev/nvme0n1p2", "/dev/sr0"] {
        let err = err_of(plan_unblock(&host, &flat, dev, UnblockMode::Raw));
        assert!(
            err.contains("protected by the dfnix registry"),
            "{dev}: {err}"
        );
        assert!(
            err_of(mount_evidence(&host, &flat, dev, None)).contains("protected"),
            "{dev}"
        );
    }
    assert!(host.calls().is_empty(), "{:?}", host.calls());
    // Evidence and target disks are untouched by the registry
    assert!(plan_unblock(&host, &flat, "/dev/sdc1", UnblockMode::Target).is_ok());
}

#[test]
fn every_action_is_audited_with_its_outcome() {
    let host = FakeHost::new()
        .respond("blkid -p -o export /dev/sdb2", 0, "TYPE=ext4\n")
        .respond("umount /media/evidence/sdb2", 1, "");
    mount_evidence(&host, &lab(), "/dev/sdb2", None).unwrap();
    let _ = mount_evidence(&host, &lab(), "/dev/nvme0n1p1", None);
    // A container is declined before anything is mounted: refused, not an error
    let host_luks = FakeHost::new().respond(
        "blkid -p -o export /dev/sdc2",
        0,
        "TYPE=crypto_LUKS\nUSAGE=crypto\n",
    );
    let _ = mount_evidence(&host_luks, &lab(), "/dev/sdc2", None);
    assert_eq!(
        host_luks.events(),
        [("evidence_mount".to_string(), Outcome::Refused)]
    );
    // A mount that is attempted and fails is an error
    let host_fail = FakeHost::new()
        .respond("blkid -p -o export /dev/sdb2", 0, "TYPE=xfs\n")
        .fail("mount -t xfs -o ro,noatime,nodev,nosuid,noexec,norecovery /dev/sdb2 /media/evidence/sdb2");
    let _ = mount_evidence(&host_fail, &lab(), "/dev/sdb2", None);
    assert_eq!(
        host_fail.events(),
        [("evidence_mount".to_string(), Outcome::Error)]
    );
    let plan = plan_unblock(&host, &lab(), "/dev/sdc1", UnblockMode::Target).unwrap();
    record_unconfirmed(&host, &lab(), &plan, "sdc");
    mount_target(&host, &lab(), &plan, None).unwrap();
    let _ = plan_unblock(&host, &lab(), "/dev/sdb2", UnblockMode::Target);
    let _ = unmount_device(&host, "/media/evidence/sdb2");

    assert_eq!(
        host.events(),
        [
            ("evidence_mount".to_string(), Outcome::Ok),
            ("evidence_mount".to_string(), Outcome::Refused),
            ("unblock_refused".to_string(), Outcome::Refused),
            ("target_mount".to_string(), Outcome::Ok),
            ("unblock_refused".to_string(), Outcome::Refused),
            ("umount".to_string(), Outcome::Error),
        ]
    );
    let events = host.events.borrow();
    let mount = &events[0];
    assert_eq!(mount.device.as_ref().unwrap().path, "/dev/sdb2");
    assert_eq!(mount.details["fstype"], "ext4");
    assert_eq!(mount.details["ro_verified"], true);
    assert_eq!(mount.details["disk"]["serial"], "WD-EVID001");
    assert_eq!(events[2].details["typed"], "sdc");
    assert_eq!(
        events[3].details["writable"],
        serde_json::json!(["/dev/sdc", "/dev/sdc1"])
    );
    assert_eq!(events[3].details["mountpoint"], "/media/target/sdc1");
}

// ---------------------------------------------------------------------------
// Read-only unlock of encrypted evidence volumes
// ---------------------------------------------------------------------------

fn crypt_host(blkid_type: &str) -> FakeHost {
    FakeHost::new()
        .respond(
            "blkid -p -o export /dev/sdb2",
            0,
            &format!("DEVNAME=/dev/sdb2\nTYPE={blkid_type}\n"),
        )
        // No mapping of that name yet
        .respond("dmsetup info ev_sdb2", 1, "")
}

#[test]
fn unlock_opens_read_only_after_locking_the_device() {
    let flat = lab();
    let host = crypt_host("crypto_LUKS");
    let msg = unlock(&host, &flat, "/dev/sdb2", CryptKind::Auto, None, None).unwrap();
    assert!(msg.contains("/dev/mapper/ev_sdb2"), "{msg}");
    let calls = host.calls();
    let setro = calls
        .iter()
        .position(|c| c == "blockdev --setro /dev/sdb2")
        .unwrap();
    let open = calls
        .iter()
        .position(|c| c == "tty cryptsetup open --readonly --type luks /dev/sdb2 ev_sdb2")
        .unwrap();
    assert!(setro < open, "{calls:?}");
    assert!(calls.contains(&"blockdev --getro /dev/mapper/ev_sdb2".to_string()));
    assert_eq!(host.events(), [("volume_unlock".to_string(), Outcome::Ok)]);
    let details = &host.events.borrow()[0].details;
    assert_eq!(details["key_source"], "typed at the terminal");
}

#[test]
fn unlock_bitlocker_and_named_formats() {
    let flat = lab();
    let host = crypt_host("BitLocker");
    unlock(&host, &flat, "/dev/sdb2", CryptKind::Auto, None, None).unwrap();
    assert!(host
        .calls()
        .contains(&"tty cryptsetup open --readonly --type bitlk /dev/sdb2 ev_sdb2".to_string()));

    let host = crypt_host("");
    unlock(
        &host,
        &flat,
        "/dev/sdb2",
        CryptKind::Veracrypt,
        Some("vc1"),
        Some("/root/key"),
    )
    .unwrap_err();
    // vc1 "exists": the fake answers every unknown command with success
    let host = crypt_host("").respond("dmsetup info vc1", 1, "");
    unlock(
        &host,
        &flat,
        "/dev/sdb2",
        CryptKind::Veracrypt,
        Some("vc1"),
        Some("/root/key"),
    )
    .unwrap();
    assert!(host.calls().contains(
        &"tty cryptsetup open --readonly --type tcrypt --veracrypt --key-file /root/key /dev/sdb2 vc1"
            .to_string()
    ));
}

#[test]
fn unlock_refuses_what_it_cannot_open_safely() {
    let flat = lab();
    // System disk: refused before anything runs
    let host = crypt_host("crypto_LUKS");
    let err = err_of(unlock(
        &host,
        &flat,
        "/dev/nvme0n1p2",
        CryptKind::Auto,
        None,
        None,
    ));
    assert!(err.contains("operating system"), "{err}");
    assert!(!host.calls().iter().any(|c| c.contains("cryptsetup")));
    assert_eq!(
        host.events(),
        [("volume_unlock".to_string(), Outcome::Refused)]
    );

    // No signature, and APFS
    for (ty, hint) in [("ext4", "--type veracrypt"), ("apfs", "apfs-fuse")] {
        let host = crypt_host(ty);
        let err = err_of(unlock(
            &host,
            &flat,
            "/dev/sdb2",
            CryptKind::Auto,
            None,
            None,
        ));
        assert!(err.contains(hint), "{err}");
        assert!(!host.calls().iter().any(|c| c.contains("cryptsetup")));
    }

    // A name that is not a plain mapper name
    let host = crypt_host("crypto_LUKS");
    let err = err_of(unlock(
        &host,
        &flat,
        "/dev/sdb2",
        CryptKind::Auto,
        Some("../x"),
        None,
    ));
    assert!(err.contains("mapping name"), "{err}");
}

#[test]
fn unlock_failures_are_errors_and_a_writable_mapping_is_closed() {
    let flat = lab();
    let host = crypt_host("crypto_LUKS").interactive_exit(2);
    let err = err_of(unlock(
        &host,
        &flat,
        "/dev/sdb2",
        CryptKind::Auto,
        None,
        None,
    ));
    assert!(err.contains("wrong passphrase"), "{err}");
    assert_eq!(
        host.events(),
        [("volume_unlock".to_string(), Outcome::Error)]
    );

    let host = crypt_host("crypto_LUKS").writable("/dev/mapper/ev_sdb2");
    let err = err_of(unlock(
        &host,
        &flat,
        "/dev/sdb2",
        CryptKind::Auto,
        None,
        None,
    ));
    assert!(err.contains("not read-only"), "{err}");
    assert!(host
        .calls()
        .contains(&"cryptsetup close ev_sdb2".to_string()));

    let host = FakeHost::new();
    lock(&host, &flat, "ev_sdb2").unwrap();
    assert!(host
        .calls()
        .contains(&"cryptsetup close ev_sdb2".to_string()));
    assert_eq!(host.events(), [("volume_lock".to_string(), Outcome::Ok)]);
}

// ---------------------------------------------------------------------------
// Read-only reassembly from member images
// ---------------------------------------------------------------------------

fn images(host: FakeHost, names: &[&str]) -> FakeHost {
    let mut host = host;
    for (i, n) in names.iter().enumerate() {
        host = host
            .file(&format!("/cases/{n}"), "")
            .respond(
                &format!("losetup -r -f --show /cases/{n}"),
                0,
                &format!("/dev/loop{i}\n"),
            )
            .respond(
                &format!("losetup -r -f --show -P /cases/{n}"),
                0,
                &format!("/dev/loop{i}\n"),
            );
    }
    host
}

fn members(names: &[&str]) -> Vec<String> {
    names.iter().map(|n| format!("/cases/{n}")).collect()
}

#[test]
fn md_is_assembled_read_only_from_read_only_loops_and_taken_apart() {
    let flat = lab();
    // /sys/block/md100 itself is absent, so md100 is free; its array_state is
    // what the kernel shows once the array runs
    let host = images(FakeHost::new(), &["a.raw", "b.raw"])
        .file("/sys/block/md100/md/array_state", "readonly\n");
    let msg = assemble(&host, &flat, Kind::Md, &members(&["a.raw", "b.raw"]), None).unwrap();
    assert!(msg.contains("/dev/md100"), "{msg}");
    let calls = host.calls();
    assert!(
        calls.contains(&"mdadm --assemble --readonly /dev/md100 /dev/loop0 /dev/loop1".to_string()),
        "{calls:?}"
    );
    assert!(calls.contains(&"blockdev --getro /dev/loop1".to_string()));
    let state: serde_json::Value =
        serde_json::from_str(&host.read_file("/run/dfnix/assembled/md100.json").unwrap()).unwrap();
    assert_eq!(
        state["loops"],
        serde_json::json!(["/dev/loop0", "/dev/loop1"])
    );
    assert_eq!(host.events(), [("raid_assemble".to_string(), Outcome::Ok)]);

    disassemble(&host, "md100").unwrap();
    let calls = host.calls();
    assert!(calls.contains(&"mdadm --stop /dev/md100".to_string()));
    assert!(calls.contains(&"losetup -d /dev/loop0".to_string()));
    assert!(!host.exists("/run/dfnix/assembled/md100.json"));
}

#[test]
fn an_array_that_is_not_read_only_is_stopped_and_detached() {
    let flat = lab();
    let host = images(FakeHost::new(), &["a.raw"]);
    // md100 exists already: md101 is used
    let host = host
        .file("/sys/block/md100", "")
        .file("/sys/block/md101/md/array_state", "clean\n");
    let err = err_of(assemble(&host, &flat, Kind::Md, &members(&["a.raw"]), None));
    assert!(err.contains("not readonly"), "{err}");
    let calls = host.calls();
    assert!(
        calls.contains(&"mdadm --stop /dev/md101".to_string()),
        "{calls:?}"
    );
    assert!(calls.contains(&"losetup -d /dev/loop0".to_string()));
    assert_eq!(
        host.events(),
        [("raid_assemble".to_string(), Outcome::Error)]
    );
}

#[test]
fn system_disks_and_missing_images_are_refused_before_any_loop() {
    let flat = lab();
    let host = FakeHost::new();
    let err = err_of(assemble(
        &host,
        &flat,
        Kind::Md,
        &["/dev/nvme0n1".into()],
        None,
    ));
    assert!(err.contains("operating system"), "{err}");
    let err = err_of(assemble(
        &host,
        &flat,
        Kind::Md,
        &members(&["missing.raw"]),
        None,
    ));
    assert!(err.contains("no such image"), "{err}");
    assert!(!host.calls().iter().any(|c| c.starts_with("losetup")));
    assert_eq!(
        host.events(),
        [
            ("raid_assemble".to_string(), Outcome::Refused),
            ("raid_assemble".to_string(), Outcome::Refused)
        ]
    );
    // A member disk is locked read-only before it is looped
    let host = FakeHost::new().respond("losetup -r -f --show /dev/sdd", 0, "/dev/loop0\n");
    let _ = assemble(&host, &flat, Kind::Md, &["/dev/sdd".into()], None);
    let calls = host.calls();
    let setro = calls
        .iter()
        .position(|c| c == "blockdev --setro /dev/sdd")
        .unwrap();
    let lo = calls
        .iter()
        .position(|c| c == "losetup -r -f --show /dev/sdd")
        .unwrap();
    assert!(setro < lo, "{calls:?}");
}

#[test]
fn lvm_activates_read_only_through_the_loops_only() {
    let flat = lab();
    let config =
        "global { metadata_read_only = 1 } activation { read_only_volume_list = [ \"evvg\" ] }";
    let host = images(FakeHost::new(), &["pv.raw"])
        .respond(
            "pvs --devices /dev/loop0 --noheadings -o vg_name",
            0,
            "  evvg\n",
        )
        .respond(
            "lvs --devices /dev/loop0 --noheadings -o lv_path evvg",
            0,
            "  /dev/evvg/evlv\n",
        );
    assemble(
        &host,
        &flat,
        Kind::Lvm,
        &members(&["pv.raw"]),
        Some("case1"),
    )
    .unwrap();
    assert!(host.calls().contains(&format!(
        "vgchange -ay --devices /dev/loop0 --config {config} evvg"
    )));
    disassemble(&host, "case1").unwrap();
    assert!(host.calls().contains(&format!(
        "vgchange -an --devices /dev/loop0 --config {config} evvg"
    )));

    // A writable logical volume is deactivated again
    let host = images(FakeHost::new(), &["pv.raw"])
        .respond(
            "pvs --devices /dev/loop0 --noheadings -o vg_name",
            0,
            "  evvg\n",
        )
        .respond(
            "lvs --devices /dev/loop0 --noheadings -o lv_path evvg",
            0,
            "  /dev/evvg/evlv\n",
        )
        .writable("/dev/evvg/evlv");
    let err = err_of(assemble(
        &host,
        &flat,
        Kind::Lvm,
        &members(&["pv.raw"]),
        None,
    ));
    assert!(err.contains("not read-only"), "{err}");
    assert!(host.calls().contains(&format!(
        "vgchange -an --devices /dev/loop0 --config {config} evvg"
    )));

    // Members of two volume groups
    let host = images(FakeHost::new(), &["a.raw", "b.raw"]).respond(
        "pvs --devices /dev/loop0,/dev/loop1 --noheadings -o vg_name",
        0,
        "  vg1\n  vg2\n",
    );
    let err = err_of(assemble(
        &host,
        &flat,
        Kind::Lvm,
        &members(&["a.raw", "b.raw"]),
        None,
    ));
    assert!(err.contains("2 volume groups"), "{err}");
}

#[test]
fn zfs_imports_read_only_from_partitioned_loops() {
    let flat = lab();
    let host = images(FakeHost::new(), &["z.raw"])
        .file("/dev/loop0p1", "")
        .respond(
            "zpool import -d /dev/loop0 -d /dev/loop0p1",
            0,
            "   pool: evpool\n     id: 42\n  state: ONLINE\n",
        )
        .respond("zpool get -H -o value readonly evpool", 0, "on\n");
    let msg = assemble(&host, &flat, Kind::Zfs, &members(&["z.raw"]), None).unwrap();
    assert!(msg.contains("/media/evidence/zfs_evpool"), "{msg}");
    let calls = host.calls();
    assert!(calls.contains(&"losetup -r -f --show -P /cases/z.raw".to_string()));
    assert!(calls.contains(
        &"zpool import -o readonly=on -o cachefile=none -N -R /media/evidence/zfs_evpool -f -d /dev/loop0 -d /dev/loop0p1 evpool"
            .to_string()
    ), "{calls:?}");
    disassemble(&host, "evpool").unwrap();
    assert!(host.calls().contains(&"zpool export evpool".to_string()));

    // Imported but not read-only: exported again
    let host = images(FakeHost::new(), &["z.raw"])
        .respond("zpool import -d /dev/loop0", 0, "   pool: evpool\n")
        .respond("zpool get -H -o value readonly evpool", 0, "off\n");
    let err = err_of(assemble(
        &host,
        &flat,
        Kind::Zfs,
        &members(&["z.raw"]),
        None,
    ));
    assert!(err.contains("not imported read-only"), "{err}");
    assert!(host.calls().contains(&"zpool export evpool".to_string()));
}

#[test]
fn review_fixes_teardown_symlinks_and_mapper_names() {
    let flat = lab();
    // A symlink to the system disk is a device, refused before any loop
    let host = FakeHost::new().alias("/cases/disk.raw", "/dev/nvme0n1");
    let err = err_of(assemble(
        &host,
        &flat,
        Kind::Md,
        &members(&["disk.raw"]),
        None,
    ));
    assert!(err.contains("operating system"), "{err}");
    assert!(!host.calls().iter().any(|c| c.starts_with("losetup")));

    // lvs fails after activation: the volume group is deactivated again
    let host = images(FakeHost::new(), &["pv.raw"])
        .respond(
            "pvs --devices /dev/loop0 --noheadings -o vg_name",
            0,
            "  evvg\n",
        )
        .fail("lvs --devices /dev/loop0 --noheadings -o lv_path evvg");
    assemble(&host, &flat, Kind::Lvm, &members(&["pv.raw"]), None).unwrap_err();
    assert!(host.calls().iter().any(|c| c.starts_with("vgchange -an")));
    assert!(host.calls().contains(&"losetup -d /dev/loop0".to_string()));

    // zpool get fails after the import: exported again
    let host = images(FakeHost::new(), &["z.raw"])
        .respond("zpool import -d /dev/loop0", 0, "   pool: evpool\n")
        .fail("zpool get -H -o value readonly evpool");
    assemble(&host, &flat, Kind::Zfs, &members(&["z.raw"]), None).unwrap_err();
    assert!(host.calls().contains(&"zpool export evpool".to_string()));

    // The default name is taken: the array is stopped again
    let host = images(FakeHost::new(), &["a.raw"])
        .file("/sys/block/md100/md/array_state", "readonly\n")
        .file("/run/dfnix/assembled/md100.json", "{}");
    let err = err_of(assemble(&host, &flat, Kind::Md, &members(&["a.raw"]), None));
    assert!(err.contains("exists"), "{err}");
    assert!(host
        .calls()
        .contains(&"mdadm --stop /dev/md100".to_string()));

    // lock takes the mapper path, and refuses anything but a plain name
    let host = FakeHost::new();
    lock(&host, &flat, "/dev/mapper/ev_sdb2").unwrap();
    assert!(host
        .calls()
        .contains(&"cryptsetup close ev_sdb2".to_string()));
    let err = err_of(lock(&host, &flat, "../../dev/sda"));
    assert!(err.contains("mapping name"), "{err}");
}
