use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use dfmount::{
    assemble::{assemble, disassemble, Kind as AssembleKind},
    devices::{fetch_devices, FlatDevice},
    ops::{
        lock, mount_evidence, mount_target, plan_unblock, record_unconfirmed, unblock_device,
        unlock, unmount_device, CryptKind, UnblockMode, UnblockPlan,
    },
    sys::{RealSystem, System},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table, TableState, Wrap},
    Terminal,
};
use std::{
    io::{self, BufRead, IsTerminal, Write},
    process::Command,
    time::Duration,
};

#[derive(Parser, Debug)]
#[command(
    name = "dfmount",
    version,
    about = "Modern Forensic Storage Mounter & Target Unblocker TUI"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Print connected storage matrix and read-only status
    Status,
    /// Mount partition write-blocked with zero journal replay
    Evidence {
        device: String,
        target: Option<String>,
    },
    /// Mount target drive writeable for dfdisk output
    Target {
        device: String,
        target: Option<String>,
        /// Kernel name of the device (e.g. sdc1), required when stdin is not a terminal
        #[arg(long)]
        confirm: Option<String>,
    },
    /// Unblock raw block device for direct disk cloning
    Unblock {
        device: String,
        /// Kernel name of the device (e.g. sdc), required when stdin is not a terminal
        #[arg(long)]
        confirm: Option<String>,
    },
    /// Safely flush and unmount partition
    Umount { target: String },
    /// Open an encrypted evidence volume read-only (LUKS, BitLocker, VeraCrypt,
    /// TrueCrypt, FileVault 2) with cryptsetup
    Unlock {
        device: String,
        #[arg(long = "type", value_enum, default_value = "auto")]
        kind: CryptKind,
        /// Name under /dev/mapper (default: ev_<device>)
        #[arg(long)]
        name: Option<String>,
        /// Read the key from this file instead of asking at the terminal
        #[arg(long)]
        key_file: Option<String>,
    },
    /// Close a volume opened with unlock
    Lock { name: String },
    /// Reassemble md RAID, LVM or ZFS read-only from member images (or disks)
    /// through read-only loop devices
    Assemble {
        #[arg(long, value_enum)]
        kind: AssembleKind,
        /// Member images or devices, in any order
        #[arg(required = true)]
        members: Vec<String>,
        /// Name for disassemble (default: md device, volume group or pool)
        #[arg(long)]
        name: Option<String>,
    },
    /// Take apart an assembly and detach its loop devices
    Disassemble { name: String },
}

#[derive(Debug, Clone, Copy)]
enum PendingKind {
    Target,
    Unblock,
}

/// A write-enabling action waiting for the examiner to type the device name
struct Pending {
    kind: PendingKind,
    plan: UnblockPlan,
    typed: String,
}

/// Rescan before acting so a key press never lands on a drive that was swapped
/// in under the same kernel name since the table was drawn.
fn rescan_selected(
    sys: &dyn System,
    devices: &mut Vec<FlatDevice>,
    selected: &FlatDevice,
) -> Result<String> {
    let path = selected.device.dev_path();
    let fresh = fetch_devices(sys)?;
    let identity = |f: &FlatDevice| {
        (
            f.device.serial.clone(),
            f.device.model.clone(),
            f.device.size.clone(),
        )
    };
    let unchanged = fresh
        .iter()
        .find(|f| f.device.dev_path() == path)
        .map(identity)
        == Some(identity(selected));
    *devices = fresh;
    if !unchanged {
        bail!(
            "{} changed since the last scan (hotplug?). Table refreshed, check the selection.",
            path
        );
    }
    Ok(path)
}

fn confirm_cli(
    sys: &dyn System,
    flat: &[FlatDevice],
    plan: &UnblockPlan,
    confirm: Option<&str>,
) -> Result<()> {
    eprintln!("[!] {}", plan.summary());
    let typed = match confirm {
        Some(c) => c.to_string(),
        None if io::stdin().is_terminal() => {
            eprint!("[?] Type '{}' to confirm: ", plan.confirm_name);
            io::stderr().flush()?;
            let mut line = String::new();
            io::stdin().lock().read_line(&mut line)?;
            line
        }
        None => bail!(
            "stdin is not a terminal; pass --confirm {} to confirm",
            plan.confirm_name
        ),
    };
    if !plan.confirms(&typed) {
        record_unconfirmed(sys, flat, plan, &typed);
        bail!(
            "Confirmation did not match '{}'; nothing was changed",
            plan.confirm_name
        );
    }
    Ok(())
}

fn run_tui() -> Result<()> {
    let sys = RealSystem;
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut table_state = TableState::default();
    table_state.select(Some(0));

    let mut devices = fetch_devices(&sys).unwrap_or_default();
    let mut status_msg = String::from("Ready. Select device with j/k or ↑/↓ and choose an action.");
    let mut is_error = false;
    let mut pending: Option<Pending> = None;

    loop {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3), // Header title
                    Constraint::Min(8),    // Table
                    Constraint::Length(5), // Status message / confirmation prompt
                    Constraint::Length(2), // Bottom hotkey bar
                ])
                .split(f.area());

            // 1. Header
            let title = Paragraph::new(Line::from(vec![
                Span::styled(
                    " dfmount ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("— Forensic Media Mounter & Ingestion Manager (dfnix)"),
            ]))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
            f.render_widget(title, chunks[0]);

            // 2. Storage Table
            let rows: Vec<Row> = devices
                .iter()
                .map(|fdev| {
                    let dev = &fdev.device;
                    let indent =
                        "  ".repeat(fdev.level) + if fdev.level > 0 { "└─ " } else { "" };
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
                        (
                            "[SYSTEM]",
                            Color::Magenta,
                            format!("{} (SYS PROTECT)", mountpoint),
                        )
                    } else if ro {
                        (
                            "🔒 RO-LOCKED",
                            Color::Green,
                            if mountpoint != "-" {
                                format!("{} (EVIDENCE)", mountpoint)
                            } else {
                                "UNMOUNTED (SAFE)".to_string()
                            },
                        )
                    } else {
                        (
                            "💾 RW-TARGET",
                            Color::Red,
                            if mountpoint != "-" {
                                format!("{} (TARGET)", mountpoint)
                            } else {
                                "UNBLOCKED (RW)".to_string()
                            },
                        )
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
                        Span::styled(
                            ro_text,
                            Style::default().fg(ro_color).add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(fstype),
                        Span::raw(role_text),
                        Span::raw(model_serial),
                    ])
                })
                .collect();

            let header_row = Row::new(vec![
                Span::styled(
                    "DEVICE",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "SIZE",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "STATUS",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "FS",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "MOUNTPOINT / ROLE",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "MODEL / SERIAL",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
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
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Storage Devices ")
                    .border_style(Style::default().fg(Color::DarkGray)),
            )
            .row_highlight_style(
                Style::default()
                    .bg(Color::Rgb(30, 45, 55))
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            );

            f.render_stateful_widget(table, chunks[1], &mut table_state);

            // 3. Status Box
            let status_line = match &pending {
                Some(p) => Line::from(vec![
                    Span::styled(
                        " CONFIRM ",
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!(
                            "{}. Type '{}' + Enter to proceed, Esc to cancel: ",
                            p.plan.summary(),
                            p.plan.confirm_name
                        ),
                        Style::default().fg(Color::Yellow),
                    ),
                    Span::styled(
                        p.typed.clone(),
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
                None => {
                    let status_color = if is_error { Color::Red } else { Color::Green };
                    Line::from(vec![
                        Span::styled(
                            " >> ",
                            Style::default()
                                .fg(status_color)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(status_msg.clone(), Style::default().fg(status_color)),
                    ])
                }
            };
            let status_p = Paragraph::new(status_line).wrap(Wrap { trim: true }).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
            f.render_widget(status_p, chunks[2]);

            // 4. Hotkeys Footer
            let footer = Paragraph::new(Line::from(vec![
                Span::styled(
                    " [E] ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("Evid-RO  "),
                Span::styled(
                    " [T] ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("Target-RW  "),
                Span::styled(
                    " [U] ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("Unblock  "),
                Span::styled(
                    " [X] ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("Umount  "),
                Span::styled(
                    " [D] ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("dfdisk  "),
                Span::styled(
                    " [R] ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("Rescan  "),
                Span::styled(
                    " [Q] ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("Quit "),
            ]));
            f.render_widget(footer, chunks[3]);
        })?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if let Some(p) = pending.as_mut() {
                    match key.code {
                        KeyCode::Esc => {
                            pending = None;
                            status_msg = "Cancelled; nothing was changed.".to_string();
                            is_error = false;
                        }
                        KeyCode::Backspace => {
                            p.typed.pop();
                        }
                        KeyCode::Char(c) => p.typed.push(c),
                        KeyCode::Enter => {
                            let p = pending.take().unwrap();
                            let res = if !p.plan.confirms(&p.typed) {
                                record_unconfirmed(&sys, &devices, &p.plan, &p.typed);
                                Err(anyhow::anyhow!(
                                    "Confirmation did not match '{}'; nothing was changed",
                                    p.plan.confirm_name
                                ))
                            } else {
                                match p.kind {
                                    PendingKind::Target => {
                                        mount_target(&sys, &devices, &p.plan, None)
                                    }
                                    PendingKind::Unblock => unblock_device(&sys, &devices, &p.plan),
                                }
                            };
                            match res {
                                Ok(msg) => {
                                    status_msg = msg;
                                    is_error = false;
                                }
                                Err(e) => {
                                    status_msg = format!("{:#}", e);
                                    is_error = true;
                                }
                            }
                            devices = fetch_devices(&sys).unwrap_or_default();
                        }
                        _ => {}
                    }
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Up | KeyCode::Char('k') => {
                        let i = match table_state.selected() {
                            Some(i) => {
                                if i > 0 {
                                    i - 1
                                } else {
                                    devices.len().saturating_sub(1)
                                }
                            }
                            None => 0,
                        };
                        table_state.select(Some(i));
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let i = match table_state.selected() {
                            Some(i) if i < devices.len().saturating_sub(1) => i + 1,
                            Some(_) | None => 0,
                        };
                        table_state.select(Some(i));
                    }
                    KeyCode::Char('r') => {
                        devices = fetch_devices(&sys).unwrap_or_default();
                        status_msg = "Rescanned storage media.".to_string();
                        is_error = false;
                    }
                    KeyCode::Char(c @ ('e' | 't' | 'u')) => {
                        let Some(selected) =
                            table_state.selected().and_then(|i| devices.get(i)).cloned()
                        else {
                            continue;
                        };
                        let res =
                            rescan_selected(&sys, &mut devices, &selected).and_then(
                                |path| match c {
                                    'e' => {
                                        let msg = mount_evidence(&sys, &devices, &path, None);
                                        devices = fetch_devices(&sys).unwrap_or_default();
                                        msg.map(Some)
                                    }
                                    't' => plan_unblock(&sys, &devices, &path, UnblockMode::Target)
                                        .map(|plan| {
                                            pending = Some(Pending {
                                                kind: PendingKind::Target,
                                                plan,
                                                typed: String::new(),
                                            });
                                            None
                                        }),
                                    _ => plan_unblock(&sys, &devices, &path, UnblockMode::Raw).map(
                                        |plan| {
                                            pending = Some(Pending {
                                                kind: PendingKind::Unblock,
                                                plan,
                                                typed: String::new(),
                                            });
                                            None
                                        },
                                    ),
                                },
                            );
                        match res {
                            Ok(Some(msg)) => {
                                status_msg = msg;
                                is_error = false;
                            }
                            Ok(None) => {}
                            Err(e) => {
                                status_msg = format!("{:#}", e);
                                is_error = true;
                            }
                        }
                    }
                    KeyCode::Char('x') => {
                        if let Some(idx) = table_state.selected() {
                            if let Some(fdev) = devices.get(idx) {
                                let path = fdev
                                    .device
                                    .path
                                    .clone()
                                    .unwrap_or_else(|| format!("/dev/{}", fdev.device.name));
                                match unmount_device(&sys, &path) {
                                    Ok(msg) => {
                                        status_msg = msg;
                                        is_error = false;
                                    }
                                    Err(e) => {
                                        status_msg = e.to_string();
                                        is_error = true;
                                    }
                                }
                                devices = fetch_devices(&sys).unwrap_or_default();
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
                        devices = fetch_devices(&sys).unwrap_or_default();
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
    let sys = RealSystem;

    match cli.command {
        Some(Commands::Status) => {
            let devs = fetch_devices(&sys)?;
            println!(
                "{:<14} {:<8} {:<12} {:<8} {:<24} MODEL / SERIAL",
                "DEVICE", "SIZE", "STATUS", "FS", "MOUNTPOINT"
            );
            println!("{}", "-".repeat(80));
            for fdev in devs {
                let dev = &fdev.device;
                let indent = "  ".repeat(fdev.level);
                let name = format!("{}{}", indent, dev.name);
                let size = dev.size.as_deref().unwrap_or("-");
                let fstype = dev.fstype.as_deref().unwrap_or("-");
                let ro = dev.ro.unwrap_or(false);
                let status = if fdev.is_system {
                    "[SYSTEM]"
                } else if ro {
                    "RO-LOCKED"
                } else {
                    "RW-TARGET"
                };
                let mount = dev.mounts().next().unwrap_or("-");
                println!(
                    "{:<14} {:<8} {:<12} {:<8} {:<24}",
                    name, size, status, fstype, mount
                );
            }
        }
        Some(Commands::Evidence { device, target }) => {
            let devs = fetch_devices(&sys)?;
            let res = mount_evidence(&sys, &devs, &device, target.as_deref())?;
            println!("[✓] {}", res);
        }
        Some(Commands::Target {
            device,
            target,
            confirm,
        }) => {
            let devs = fetch_devices(&sys)?;
            let plan = plan_unblock(&sys, &devs, &device, UnblockMode::Target)?;
            confirm_cli(&sys, &devs, &plan, confirm.as_deref())?;
            let res = mount_target(&sys, &devs, &plan, target.as_deref())?;
            println!("[✓] {}", res);
        }
        Some(Commands::Unblock { device, confirm }) => {
            let devs = fetch_devices(&sys)?;
            let plan = plan_unblock(&sys, &devs, &device, UnblockMode::Raw)?;
            confirm_cli(&sys, &devs, &plan, confirm.as_deref())?;
            let res = unblock_device(&sys, &devs, &plan)?;
            println!("[✓] {}", res);
        }
        Some(Commands::Unlock {
            device,
            kind,
            name,
            key_file,
        }) => {
            let devs = fetch_devices(&sys)?;
            let res = unlock(
                &sys,
                &devs,
                &device,
                kind,
                name.as_deref(),
                key_file.as_deref(),
            )?;
            println!("[✓] {}", res);
        }
        Some(Commands::Lock { name }) => {
            let devs = fetch_devices(&sys)?;
            let res = lock(&sys, &devs, &name)?;
            println!("[✓] {}", res);
        }
        Some(Commands::Assemble {
            kind,
            members,
            name,
        }) => {
            let devs = fetch_devices(&sys)?;
            let res = assemble(&sys, &devs, kind, &members, name.as_deref())?;
            println!("[✓] {}", res);
        }
        Some(Commands::Disassemble { name }) => {
            let res = disassemble(&sys, &name)?;
            println!("[✓] {}", res);
        }
        Some(Commands::Umount { target }) => {
            let res = unmount_device(&sys, &target)?;
            println!("[✓] {}", res);
        }
        None => {
            run_tui()?;
        }
    }

    Ok(())
}
