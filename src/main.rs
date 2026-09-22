use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table, TableState},
    Terminal,
};
use serde::{Deserialize, Serialize};
use std::{
    io,
    process::Command,
    time::Duration,
};

#[derive(Parser, Debug)]
#[command(name = "dfmount", version, about = "Modern Forensic Storage Mounter & Target Unblocker TUI")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Print connected storage matrix and read-only status
    Status,
    /// Mount partition write-blocked with zero journal replay
    Evidence { device: String, target: Option<String> },
    /// Mount target drive writeable for dfdisk output
    Target { device: String, target: Option<String> },
    /// Unblock raw block device for direct disk cloning
    Unblock { device: String },
    /// Safely flush and unmount partition
    Umount { target: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockDevice {
    name: String,
    path: Option<String>,
    size: Option<String>,
    ro: Option<bool>,
    #[serde(rename = "type")]
    dev_type: Option<String>,
    fstype: Option<String>,
    label: Option<String>,
    mountpoints: Option<Vec<Option<String>>>,
    model: Option<String>,
    serial: Option<String>,
    children: Option<Vec<BlockDevice>>,
}

#[derive(Debug, Deserialize)]
struct LsblkOutput {
    blockdevices: Vec<BlockDevice>,
}

#[derive(Debug, Clone)]
struct FlatDevice {
    device: BlockDevice,
    level: usize,
    is_system: bool,
}

fn is_mount_system(m: &str) -> bool {
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

fn is_system_device(dev: &BlockDevice) -> bool {
    if dev.label.as_deref() == Some("DFNIX_LIVE") {
        return true;
    }
    if let Some(mounts) = &dev.mountpoints {
        for m in mounts.iter().flatten() {
            if is_mount_system(m) {
                return true;
            }
        }
    }
    if let Some(children) = &dev.children {
        for c in children {
            if is_system_device(c) {
                return true;
            }
        }
    }
    false
}

fn fetch_devices() -> Result<Vec<FlatDevice>> {
    let output = Command::new("lsblk")
        .args(["-J", "-o", "NAME,PATH,SIZE,RO,TYPE,FSTYPE,LABEL,MOUNTPOINTS,MODEL,SERIAL"])
        .output()
        .context("Failed to run lsblk")?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let parsed: LsblkOutput = serde_json::from_slice(&output.stdout)?;
    let mut flat = Vec::new();

    fn recurse(dev: &BlockDevice, level: usize, parent_is_sys: bool, flat: &mut Vec<FlatDevice>) {
        let is_sys = parent_is_sys || is_system_device(dev);
        flat.push(FlatDevice {
            device: dev.clone(),
            level,
            is_system: is_sys,
        });
        if let Some(children) = &dev.children {
            for c in children {
                recurse(c, level + 1, is_sys, flat);
            }
        }
    }

    for dev in &parsed.blockdevices {
        recurse(dev, 0, false, &mut flat);
    }

    Ok(flat)
}

fn mount_evidence(dev: &str, target: Option<&str>) -> Result<String> {
    // 1. Force driver read-only
    let _ = Command::new("blockdev").args(["--setro", dev]).status();

    // 2. Identify filesystem
    let blkid_out = Command::new("blkid").args(["-o", "value", "-s", "TYPE", dev]).output();
    let fstype = blkid_out
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_lowercase())
        .unwrap_or_default();

    let dev_name = std::path::Path::new(dev)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "evidence".to_string());

    let mnt_target = target
        .map(|t| t.to_string())
        .unwrap_or_else(|| format!("/media/evidence/{}", dev_name));

    let _ = std::fs::create_dir_all(&mnt_target);

    // Zero-journal replay flags based on filesystem
    let (fstype_arg, opts) = match fstype.as_str() {
        "ext3" | "ext4" => (fstype.as_str(), "ro,noload,noatime,nodev,nosuid,noexec"),
        "xfs" => ("xfs", "ro,norecovery,noatime,nodev,nosuid,noexec"),
        "btrfs" => ("btrfs", "ro,rescue=nologreplay,noatime,nodev,nosuid,noexec"),
        "ntfs" => ("ntfs3", "ro,norecover,noatime,nodev,nosuid,noexec"),
        _ => ("", "ro,noatime,nodev,nosuid,noexec"),
    };

    let mut cmd = Command::new("mount");
    if !fstype_arg.is_empty() {
        cmd.args(["-t", fstype_arg]);
    }
    cmd.args(["-o", opts, dev, &mnt_target]);

    let status = cmd.status().context("Failed to mount evidence device")?;
    if status.success() {
        Ok(format!("Forensically mounted {} at {} (0 writes / 0 journal replays)", dev, mnt_target))
    } else {
        anyhow::bail!("Mount command exited with failure for {}", dev)
    }
}

fn mount_target(dev: &str, target: Option<&str>) -> Result<String> {
    // Unblock write access
    let _ = Command::new("blockdev").args(["--setrw", dev]).status();

    let dev_name = std::path::Path::new(dev)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "target".to_string());

    let mnt_target = target
        .map(|t| t.to_string())
        .unwrap_or_else(|| format!("/media/target/{}", dev_name));

    let _ = std::fs::create_dir_all(&mnt_target);

    let status = Command::new("mount")
        .args(["-o", "rw,noatime", dev, &mnt_target])
        .status()
        .context("Failed to mount target drive")?;

    if status.success() {
        Ok(format!("Mounted TARGET {} at {} for dfdisk output", dev, mnt_target))
    } else {
        anyhow::bail!("Target mount command failed for {}", dev)
    }
}

fn unblock_device(dev: &str) -> Result<String> {
    let status = Command::new("blockdev").args(["--setrw", dev]).status()?;
    if status.success() {
        Ok(format!("UNBLOCKED: {} is now WRITABLE for raw disk cloning", dev))
    } else {
        anyhow::bail!("Failed to unblock {}", dev)
    }
}

fn unmount_device(target: &str) -> Result<String> {
    let _ = Command::new("sync").status();
    let status = Command::new("umount").arg(target).status()?;
    let _ = Command::new("sync").status();
    if status.success() {
        Ok(format!("Safely flushed and unmounted {}", target))
    } else {
        anyhow::bail!("Failed to unmount {}", target)
    }
}

fn run_tui() -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut table_state = TableState::default();
    table_state.select(Some(0));

    let mut devices = fetch_devices().unwrap_or_default();
    let mut status_msg = String::from("Ready. Select device with j/k or ↑/↓ and choose an action.");
    let mut is_error = false;

    loop {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3), // Header title
                    Constraint::Min(8),    // Table
                    Constraint::Length(3), // Status message
                    Constraint::Length(2), // Bottom hotkey bar
                ])
                .split(f.area());

            // 1. Header
            let title = Paragraph::new(Line::from(vec![
                Span::styled(" dfmount ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw("— Forensic Media Mounter & Ingestion Manager (dfnix)"),
            ]))
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)));
            f.render_widget(title, chunks[0]);

            // 2. Storage Table
            let rows: Vec<Row> = devices
                .iter()
                .map(|fdev| {
                    let dev = &fdev.device;
                    let indent = "  ".repeat(fdev.level) + if fdev.level > 0 { "└─ " } else { "" };
                    let name = format!("{}{}", indent, dev.name);
                    let size = dev.size.clone().unwrap_or_default();
                    let fstype = dev.fstype.clone().unwrap_or_else(|| "-".to_string());

                    let mountpoint = dev
                        .mountpoints
                        .as_ref()
                        .and_then(|ms| ms.iter().flatten().next().cloned())
                        .unwrap_or_else(|| "-".to_string());

                    let ro = dev.ro.unwrap_or(false);

                    let (ro_text, ro_color, role_text) = if fdev.is_system {
                        ("[SYSTEM]", Color::Magenta, format!("{} (SYS PROTECT)", mountpoint))
                    } else if ro {
                        ("🔒 RO-LOCKED", Color::Green, if mountpoint != "-" { format!("{} (EVIDENCE)", mountpoint) } else { "UNMOUNTED (SAFE)".to_string() })
                    } else {
                        ("💾 RW-TARGET", Color::Red, if mountpoint != "-" { format!("{} (TARGET)", mountpoint) } else { "UNBLOCKED (RW)".to_string() })
                    };

                    let model_serial = format!(
                        "{} {}",
                        dev.model.as_deref().unwrap_or(""),
                        dev.serial.as_deref().unwrap_or("")
                    )
                    .trim()
                    .to_string();

                    Row::new(vec![
                        Span::raw(name),
                        Span::raw(size),
                        Span::styled(ro_text, Style::default().fg(ro_color).add_modifier(Modifier::BOLD)),
                        Span::raw(fstype),
                        Span::raw(role_text),
                        Span::raw(model_serial),
                    ])
                })
                .collect();

            let header_row = Row::new(vec![
                Span::styled("DEVICE", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::styled("SIZE", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::styled("STATUS", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::styled("FS", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::styled("MOUNTPOINT / ROLE", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::styled("MODEL / SERIAL", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            ]);

            let table = Table::new(
                rows,
                [
                    Constraint::Percentage(20),
                    Constraint::Percentage(10),
                    Constraint::Percentage(15),
                    Constraint::Percentage(10),
                    Constraint::Percentage(25),
                    Constraint::Percentage(20),
                ],
            )
            .header(header_row)
            .block(Block::default().borders(Borders::ALL).title(" Storage Devices ").border_style(Style::default().fg(Color::DarkGray)))
            .row_highlight_style(Style::default().bg(Color::Rgb(30, 45, 55)).fg(Color::White).add_modifier(Modifier::BOLD));

            f.render_stateful_widget(table, chunks[1], &mut table_state);

            // 3. Status Box
            let status_color = if is_error { Color::Red } else { Color::Green };
            let status_p = Paragraph::new(Line::from(vec![
                Span::styled(" >> ", Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
                Span::styled(&status_msg, Style::default().fg(status_color)),
            ]))
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)));
            f.render_widget(status_p, chunks[2]);

            // 4. Hotkeys Footer
            let footer = Paragraph::new(Line::from(vec![
                Span::styled(" [E] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw("Evid-RO  "),
                Span::styled(" [T] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw("Target-RW  "),
                Span::styled(" [U] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw("Unblock  "),
                Span::styled(" [X] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw("Umount  "),
                Span::styled(" [D] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw("dfdisk  "),
                Span::styled(" [R] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw("Rescan  "),
                Span::styled(" [Q] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw("Quit "),
            ]));
            f.render_widget(footer, chunks[3]);
        })?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Up | KeyCode::Char('k') => {
                        let i = match table_state.selected() {
                            Some(i) => if i > 0 { i - 1 } else { devices.len().saturating_sub(1) },
                            None => 0,
                        };
                        table_state.select(Some(i));
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let i = match table_state.selected() {
                            Some(i) => if i < devices.len().saturating_sub(1) { i + 1 } else { 0 },
                            None => 0,
                        };
                        table_state.select(Some(i));
                    }
                    KeyCode::Char('r') => {
                        devices = fetch_devices().unwrap_or_default();
                        status_msg = "Rescanned storage media.".to_string();
                        is_error = false;
                    }
                    KeyCode::Char('e') => {
                        if let Some(idx) = table_state.selected() {
                            if let Some(fdev) = devices.get(idx) {
                                let path = fdev.device.path.clone().unwrap_or_else(|| format!("/dev/{}", fdev.device.name));
                                if fdev.is_system {
                                    status_msg = format!("ABORT: {} belongs to operating system!", path);
                                    is_error = true;
                                } else {
                                    match mount_evidence(&path, None) {
                                        Ok(msg) => { status_msg = msg; is_error = false; }
                                        Err(e) => { status_msg = e.to_string(); is_error = true; }
                                    }
                                    devices = fetch_devices().unwrap_or_default();
                                }
                            }
                        }
                    }
                    KeyCode::Char('t') => {
                        if let Some(idx) = table_state.selected() {
                            if let Some(fdev) = devices.get(idx) {
                                let path = fdev.device.path.clone().unwrap_or_else(|| format!("/dev/{}", fdev.device.name));
                                if fdev.is_system {
                                    status_msg = format!("ABORT: {} belongs to operating system!", path);
                                    is_error = true;
                                } else {
                                    match mount_target(&path, None) {
                                        Ok(msg) => { status_msg = msg; is_error = false; }
                                        Err(e) => { status_msg = e.to_string(); is_error = true; }
                                    }
                                    devices = fetch_devices().unwrap_or_default();
                                }
                            }
                        }
                    }
                    KeyCode::Char('u') => {
                        if let Some(idx) = table_state.selected() {
                            if let Some(fdev) = devices.get(idx) {
                                let path = fdev.device.path.clone().unwrap_or_else(|| format!("/dev/{}", fdev.device.name));
                                if fdev.is_system {
                                    status_msg = format!("ABORT: {} belongs to operating system!", path);
                                    is_error = true;
                                } else {
                                    match unblock_device(&path) {
                                        Ok(msg) => { status_msg = msg; is_error = false; }
                                        Err(e) => { status_msg = e.to_string(); is_error = true; }
                                    }
                                    devices = fetch_devices().unwrap_or_default();
                                }
                            }
                        }
                    }
                    KeyCode::Char('x') => {
                        if let Some(idx) = table_state.selected() {
                            if let Some(fdev) = devices.get(idx) {
                                let path = fdev.device.path.clone().unwrap_or_else(|| format!("/dev/{}", fdev.device.name));
                                match unmount_device(&path) {
                                    Ok(msg) => { status_msg = msg; is_error = false; }
                                    Err(e) => { status_msg = e.to_string(); is_error = true; }
                                }
                                devices = fetch_devices().unwrap_or_default();
                            }
                        }
                    }
                    KeyCode::Char('d') => {
                        disable_raw_mode()?;
                        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
                        let _ = Command::new("sudo").arg("dfdisk").status();
                        enable_raw_mode()?;
                        execute!(terminal.backend_mut(), EnterAlternateScreen)?;
                        terminal.clear()?;
                        devices = fetch_devices().unwrap_or_default();
                    }
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Status) => {
            let devs = fetch_devices()?;
            println!("{:<14} {:<8} {:<12} {:<8} {:<24} MODEL / SERIAL", "DEVICE", "SIZE", "STATUS", "FS", "MOUNTPOINT");
            println!("{}", "-".repeat(80));
            for fdev in devs {
                let dev = &fdev.device;
                let indent = "  ".repeat(fdev.level);
                let name = format!("{}{}", indent, dev.name);
                let size = dev.size.as_deref().unwrap_or("-");
                let fstype = dev.fstype.as_deref().unwrap_or("-");
                let ro = dev.ro.unwrap_or(false);
                let status = if fdev.is_system { "[SYSTEM]" } else if ro { "RO-LOCKED" } else { "RW-TARGET" };
                let mount = dev.mountpoints.as_ref().and_then(|ms| ms.iter().flatten().next().map(|s| s.as_str())).unwrap_or("-");
                println!("{:<14} {:<8} {:<12} {:<8} {:<24}", name, size, status, fstype, mount);
            }
        }
        Some(Commands::Evidence { device, target }) => {
            let res = mount_evidence(&device, target.as_deref())?;
            println!("[✓] {}", res);
        }
        Some(Commands::Target { device, target }) => {
            let res = mount_target(&device, target.as_deref())?;
            println!("[✓] {}", res);
        }
        Some(Commands::Unblock { device }) => {
            let res = unblock_device(&device)?;
            println!("[✓] {}", res);
        }
        Some(Commands::Umount { target }) => {
            let res = unmount_device(&target)?;
            println!("[✓] {}", res);
        }
        None => {
            run_tui()?;
        }
    }

    Ok(())
}
