use anyhow::{bail, Result};

/// Options shared by every evidence mount.
pub const EVIDENCE_BASE_OPTS: &str = "ro,noatime,nodev,nosuid,noexec";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountAttempt {
    pub fstype: &'static str,
    pub options: String,
}

/// Interpret `blkid -p -o export <dev>`. Low-level probing reads the device
/// itself instead of the blkid cache and reports conflicting signatures.
pub fn parse_blkid(dev: &str, code: Option<i32>, stdout: &str) -> Result<String> {
    match code {
        Some(0) => {}
        Some(2) => bail!("{}: no filesystem signature found (blkid -p); refusing to mount", dev),
        Some(8) => bail!(
            "{}: ambiguous probe result, multiple signatures found (blkid -p); refusing to mount. Inspect with `wipefs -n {}`",
            dev,
            dev
        ),
        Some(c) => bail!("{}: blkid -p failed with exit code {}; refusing to mount", dev, c),
        None => bail!("{}: blkid -p was terminated by a signal; refusing to mount", dev),
    }

    let field = |key: &str| {
        stdout
            .lines()
            .find_map(|l| l.strip_prefix(key).and_then(|v| v.strip_prefix('=')))
            .map(|v| v.trim().to_string())
    };

    let fstype = match field("TYPE") {
        Some(t) if !t.is_empty() => t.to_lowercase(),
        _ => bail!("{}: blkid -p reported no filesystem TYPE; refusing to mount", dev),
    };

    match field("USAGE").as_deref() {
        None | Some("filesystem") => Ok(fstype),
        Some("crypto") => bail!(
            "{}: {} is an encrypted container; open it read-only first (cryptsetup open --readonly) and mount the mapped device",
            dev,
            fstype
        ),
        Some(usage) => bail!("{}: {} signature ({}) is not a mountable filesystem", dev, fstype, usage),
    }
}

/// Mount attempts for a probed filesystem, tried in order. Each one is
/// read-only and suppresses journal/log replay; filesystems without a known
/// replay-safe option set are refused instead of falling back to a generic mount.
pub fn mount_plan(fstype: &str) -> Result<Vec<MountAttempt>> {
    let attempt = |fstype: &'static str, extra: &str| MountAttempt {
        fstype,
        options: if extra.is_empty() {
            EVIDENCE_BASE_OPTS.to_string()
        } else {
            format!("{},{}", EVIDENCE_BASE_OPTS, extra)
        },
    };

    Ok(match fstype {
        // The ext4 driver serves ext2/ext3 as well; noload skips journal replay
        "ext2" | "ext3" | "ext4" => vec![attempt("ext4", "noload")],
        "xfs" => vec![attempt("xfs", "norecovery")],
        "btrfs" => vec![attempt("btrfs", "rescue=nologreplay")],
        // ntfs3 rejects ntfs-3g's norecover, and neither driver touches $LogFile on a
        // read-only mount, so both get the base options; ntfs-3g covers kernels without ntfs3
        "ntfs" => vec![attempt("ntfs3", ""), attempt("ntfs-3g", "")],
        "vfat" => vec![attempt("vfat", "")],
        "exfat" => vec![attempt("exfat", "")],
        "hfsplus" => vec![attempt("hfsplus", "")],
        "iso9660" => vec![attempt("iso9660", "")],
        "udf" => vec![attempt("udf", "")],
        other => bail!(
            "unsupported filesystem type '{}': no replay-safe read-only mount options are known, refusing to mount",
            other
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blkid_plain_filesystem() {
        let out = "DEVNAME=/dev/sdb1\nUUID=1234\nTYPE=ext4\nUSAGE=filesystem\n";
        assert_eq!(parse_blkid("/dev/sdb1", Some(0), out).unwrap(), "ext4");
    }

    #[test]
    fn blkid_type_is_lowercased() {
        assert_eq!(parse_blkid("/dev/sdb1", Some(0), "TYPE=NTFS\n").unwrap(), "ntfs");
    }

    #[test]
    fn blkid_does_not_confuse_similar_keys() {
        // PTTYPE / SEC_TYPE must not be read as TYPE
        let out = "PTTYPE=dos\nSEC_TYPE=msdos\nTYPE=vfat\nUSAGE=filesystem\n";
        assert_eq!(parse_blkid("/dev/sdb1", Some(0), out).unwrap(), "vfat");
    }

    #[test]
    fn blkid_nothing_detected_is_refused() {
        let err = parse_blkid("/dev/sdb1", Some(2), "").unwrap_err().to_string();
        assert!(err.contains("no filesystem signature"), "{err}");
    }

    #[test]
    fn blkid_ambiguous_is_refused() {
        let err = parse_blkid("/dev/sdb1", Some(8), "").unwrap_err().to_string();
        assert!(err.contains("ambiguous"), "{err}");
    }

    #[test]
    fn blkid_other_failures_are_refused() {
        assert!(parse_blkid("/dev/sdb1", Some(4), "").is_err());
        assert!(parse_blkid("/dev/sdb1", None, "").is_err());
    }

    #[test]
    fn blkid_missing_type_is_refused() {
        assert!(parse_blkid("/dev/sdb1", Some(0), "UUID=1234\n").is_err());
        assert!(parse_blkid("/dev/sdb1", Some(0), "TYPE=\n").is_err());
    }

    #[test]
    fn blkid_luks_points_to_readonly_unlock() {
        let err = parse_blkid("/dev/sdb2", Some(0), "TYPE=crypto_LUKS\nUSAGE=crypto\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("--readonly"), "{err}");
    }

    #[test]
    fn blkid_non_filesystem_usage_is_refused() {
        assert!(parse_blkid("/dev/sdb3", Some(0), "TYPE=linux_raid_member\nUSAGE=raid\n").is_err());
        assert!(parse_blkid("/dev/sdb4", Some(0), "TYPE=swap\nUSAGE=other\n").is_err());
    }

    #[test]
    fn ext_family_uses_noload() {
        for fs in ["ext2", "ext3", "ext4"] {
            let plan = mount_plan(fs).unwrap();
            assert_eq!(plan.len(), 1);
            assert_eq!(plan[0].fstype, "ext4");
            assert!(plan[0].options.split(',').any(|o| o == "noload"));
        }
    }

    #[test]
    fn xfs_and_btrfs_suppress_log_replay() {
        assert!(mount_plan("xfs").unwrap()[0].options.contains("norecovery"));
        assert!(mount_plan("btrfs").unwrap()[0].options.contains("rescue=nologreplay"));
    }

    #[test]
    fn ntfs_tries_ntfs3_then_ntfs3g_without_norecover() {
        let plan = mount_plan("ntfs").unwrap();
        let types: Vec<_> = plan.iter().map(|a| a.fstype).collect();
        assert_eq!(types, ["ntfs3", "ntfs-3g"]);
        for a in &plan {
            assert!(!a.options.contains("norecover"), "{:?}", a);
        }
    }

    #[test]
    fn every_plan_is_read_only_and_hardened() {
        for fs in ["ext2", "ext3", "ext4", "xfs", "btrfs", "ntfs", "vfat", "exfat", "hfsplus", "iso9660", "udf"] {
            for a in mount_plan(fs).unwrap() {
                let opts: Vec<_> = a.options.split(',').collect();
                for required in ["ro", "noatime", "nodev", "nosuid", "noexec"] {
                    assert!(opts.contains(&required), "{fs}: {:?} lacks {required}", a);
                }
                assert!(!opts.contains(&"rw"));
            }
        }
    }

    #[test]
    fn unknown_filesystems_are_refused() {
        for fs in ["apfs", "zfs_member", "reiserfs", "", "f2fs"] {
            assert!(mount_plan(fs).is_err(), "{fs} should be refused");
        }
    }
}
