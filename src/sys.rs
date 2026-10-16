use dfcore::{audit::Event, protected::Registry};
use std::{
    io,
    process::{Command, Stdio},
};

/// Captured result of an external command.
#[derive(Debug, Clone, Default)]
pub struct CmdOutput {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOutput {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// Every side effect dfmount has on the host goes through this trait, so the
/// safety logic can be exercised in tests without root or real block devices.
pub trait System {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<CmdOutput>;
    /// Run with the terminal attached (a passphrase prompt), returning the
    /// exit code. Nothing that passes through the terminal is seen by dfmount.
    fn run_interactive(&self, program: &str, args: &[&str]) -> io::Result<Option<i32>>;
    /// Resolve symlinks such as /dev/disk/by-id/* or /dev/mapper/* to the kernel node.
    fn canonicalize(&self, path: &str) -> String;
    fn create_dir_all(&self, path: &str) -> io::Result<()>;
    fn read_file(&self, path: &str) -> io::Result<String>;
    fn write_file(&self, path: &str, content: &str) -> io::Result<()>;
    fn remove_file(&self, path: &str) -> io::Result<()>;
    fn exists(&self, path: &str) -> bool;
    /// Boot-time protected-device registry; `None` outside dfnix.
    fn protected_registry(&self) -> anyhow::Result<Option<Registry>>;
    /// Record an action in the tamper-evident audit log.
    fn audit(&self, event: Event);
}

pub struct RealSystem;

impl System for RealSystem {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<CmdOutput> {
        let out = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .output()?;
        Ok(CmdOutput {
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    fn run_interactive(&self, program: &str, args: &[&str]) -> io::Result<Option<i32>> {
        Ok(Command::new(program).args(args).status()?.code())
    }

    fn canonicalize(&self, path: &str) -> String {
        std::fs::canonicalize(path)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| path.to_string())
    }

    fn create_dir_all(&self, path: &str) -> io::Result<()> {
        std::fs::create_dir_all(path)
    }

    fn read_file(&self, path: &str) -> io::Result<String> {
        std::fs::read_to_string(path)
    }

    fn write_file(&self, path: &str, content: &str) -> io::Result<()> {
        std::fs::write(path, content)
    }

    fn remove_file(&self, path: &str) -> io::Result<()> {
        std::fs::remove_file(path)
    }

    fn exists(&self, path: &str) -> bool {
        std::path::Path::new(path).exists()
    }

    fn protected_registry(&self) -> anyhow::Result<Option<Registry>> {
        Registry::load(&dfcore::protected::path())
    }

    fn audit(&self, event: Event) {
        // The action already happened; a log failure must be loud, not fatal
        if let Err(e) = dfcore::audit::append(event) {
            eprintln!("[!] WARNING: audit log not written: {e:#}");
        }
    }
}
