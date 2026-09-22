#!/usr/bin/env python3
"""
dfmount-tui: Forensic Storage & Target Manager TUI
Designed for df-nix field operations and direct integration with dfdisk.
Zero external dependencies (uses standard python curses).
"""

import curses
import json
import os
import subprocess
import sys


def run_cmd(cmd):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except Exception as e:
        return 1, "", str(e)


def get_block_devices():
    code, out, _ = run_cmd("lsblk -J -o NAME,PATH,SIZE,RO,TYPE,FSTYPE,LABEL,MOUNTPOINTS,MODEL,SERIAL")
    if code != 0 or not out:
        return []
    try:
        data = json.loads(out)
        return data.get("blockdevices", [])
    except Exception:
        return []


def check_mount_is_system(m):
    if not m:
        return False
    if m.startswith("/run/media/") or m.startswith("/run/user/"):
        return False
    if m == "/" or m.startswith("/boot") or m.startswith("/nix") or m.startswith("/iso") or m.startswith("/sysroot") or m.startswith("/run") or m == "[SWAP]":
        return True
    return False


def is_system_device(dev):
    if not dev:
        return False
    if dev.get("is_system") is not None:
        return dev.get("is_system")
    if dev.get("label") == "DFNIX_LIVE":
        return True
    mounts = dev.get("mountpoints") or []
    for m in mounts:
        if check_mount_is_system(m):
            return True
    for child in dev.get("children", []):
        if is_system_device(child):
            return True
    return False


def flatten_devices(dev_list, level=0, parent_is_sys=False):
    flat = []
    for dev in dev_list:
        sys_dev = parent_is_sys or is_system_device(dev)
        dev["is_system"] = sys_dev
        flat.append((dev, level))
        for child in dev.get("children", []):
            flat.extend(flatten_devices([child], level + 1, parent_is_sys=sys_dev))
    return flat


class DfMountTUI:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.selected_idx = 0
        self.devices = []
        self.status_msg = "Ready. Select a device with ↑/↓ and choose an action."
        self.status_color = 2  # green by default

        # Curses initialization
        curses.curs_set(0)
        curses.use_default_colors()
        self.init_colors()
        self.refresh_devices()

    def init_colors(self):
        curses.start_color()
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)     # Header / Active
        curses.init_pair(2, curses.COLOR_GREEN, -1)                   # Safe / RO / OK
        curses.init_pair(3, curses.COLOR_RED, -1)                     # Target / Unblocked / Danger
        curses.init_pair(4, curses.COLOR_YELLOW, -1)                  # System / Warn
        curses.init_pair(5, curses.COLOR_CYAN, -1)                    # Labels / Keys
        curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_CYAN)    # Selected row

    def refresh_devices(self):
        raw_devs = get_block_devices()
        self.devices = flatten_devices(raw_devs)
        if self.selected_idx >= len(self.devices):
            self.selected_idx = max(0, len(self.devices) - 1)

    def draw(self):
        self.stdscr.clear()
        max_y, max_x = self.stdscr.getmaxyx()

        # Title bar
        title = " dfmount 🔒💾 — Forensic Media Mounter & Ingestion Manager (df-nix) "
        self.stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
        self.stdscr.addstr(0, 0, title.ljust(max_x)[:max_x])
        self.stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)

        # Header Columns
        header = f"  {'DEVICE':<14} {'SIZE':<8} {'RO/RW':<12} {'FS':<8} {'MOUNTPOINT / ROLE':<24} {'MODEL / SERIAL'}"
        self.stdscr.attron(curses.A_UNDERLINE | curses.color_pair(5))
        self.stdscr.addstr(1, 0, header.ljust(max_x)[:max_x])
        self.stdscr.attroff(curses.A_UNDERLINE | curses.color_pair(5))

        # Device Rows
        start_y = 2
        visible_rows = max_y - 6

        for i, (dev, level) in enumerate(self.devices):
            if i < 0 or i >= visible_rows:
                continue

            y = start_y + i
            is_sel = (i == self.selected_idx)

            name = dev.get("name", "")
            size = dev.get("size", "")
            ro = dev.get("ro", False)
            fstype = dev.get("fstype") or "-"
            mounts = [m for m in (dev.get("mountpoints") or []) if m]
            mountpoint = mounts[0] if mounts else "-"
            model = dev.get("model") or ""
            serial = dev.get("serial") or ""
            is_sys = is_system_device(dev)

            # Indent tree
            indent = "  " * level + ("└─ " if level > 0 else "")
            dev_label = (indent + name)[:14]

            # Role & Status Badges
            if is_sys:
                ro_text = "[SYSTEM]"
                ro_pair = 4
                role_text = f"{mountpoint} (SYS PROTECT)"
            elif ro:
                ro_text = "🔒 RO-LOCKED"
                ro_pair = 2
                role_text = f"{mountpoint} (EVIDENCE)" if mountpoint != "-" else "UNMOUNTED (SAFE)"
            else:
                ro_text = "💾 RW-TARGET"
                ro_pair = 3
                role_text = f"{mountpoint} (TARGET)" if mountpoint != "-" else "UNBLOCKED (RW)"

            info_str = f"{model} {serial}".strip() or "-"

            line = f"  {dev_label:<14} {size:<8} {ro_text:<12} {fstype:<8} {role_text:<24} {info_str}"
            line = line.ljust(max_x)[:max_x]

            if is_sel:
                self.stdscr.attron(curses.color_pair(6) | curses.A_BOLD)
                self.stdscr.addstr(y, 0, line)
                self.stdscr.attroff(curses.color_pair(6) | curses.A_BOLD)
            else:
                self.stdscr.addstr(y, 0, line[:25])
                self.stdscr.attron(curses.color_pair(ro_pair) | curses.A_BOLD)
                self.stdscr.addstr(y, 25, f"{ro_text:<12}")
                self.stdscr.attroff(curses.color_pair(ro_pair) | curses.A_BOLD)
                self.stdscr.addstr(y, 37, line[37:])

        # Status Bar
        status_line = f" >> {self.status_msg}"
        self.stdscr.attron(curses.color_pair(self.status_color) | curses.A_BOLD)
        self.stdscr.addstr(max_y - 3, 0, status_line.ljust(max_x)[:max_x])
        self.stdscr.attroff(curses.color_pair(self.status_color) | curses.A_BOLD)

        # Footer Shortcuts
        footer = " [E] Evid-RO  [T] Target-RW  [U] Unblock  [X] Umount  [D] dfdisk  [N] Net-TUI  [R] Rescan  [Q] Quit "
        self.stdscr.attron(curses.color_pair(1))
        self.stdscr.addstr(max_y - 1, 0, footer.ljust(max_x)[:max_x])
        self.stdscr.attroff(curses.color_pair(1))

        self.stdscr.refresh()

    def get_selected(self):
        if 0 <= self.selected_idx < len(self.devices):
            return self.devices[self.selected_idx][0]
        return None

    def action_mount_evidence(self):
        dev = self.get_selected()
        if not dev:
            return
        path = dev.get("path") or f"/dev/{dev.get('name')}"
        if is_system_device(dev):
            self.status_msg = f"ABORT: {path} is an OS system disk!"
            self.status_color = 3
            return

        self.status_msg = f"Mounting {path} read-only with zero journal replay..."
        self.draw()
        code, out, err = run_cmd(f"sudo df-mount evidence {path}")
        if code == 0:
            self.status_msg = f"SUCCESS: Forensically mounted {path} (0 writes / 0 journal replays)."
            self.status_color = 2
        else:
            self.status_msg = f"FAILED: {err or out}"
            self.status_color = 3
        self.refresh_devices()

    def action_mount_target(self):
        dev = self.get_selected()
        if not dev:
            return
        path = dev.get("path") or f"/dev/{dev.get('name')}"
        if is_system_device(dev):
            self.status_msg = f"ABORT: {path} is an OS system disk!"
            self.status_color = 3
            return

        self.status_msg = f"Mounting {path} as WRITEABLE TARGET for dfdisk..."
        self.draw()
        code, out, err = run_cmd(f"sudo df-mount target {path}")
        if code == 0:
            self.status_msg = f"SUCCESS: Mounted TARGET at /media/target for dfdisk ingestion."
            self.status_color = 3
        else:
            self.status_msg = f"FAILED: {err or out}"
            self.status_color = 3
        self.refresh_devices()

    def action_unblock_raw(self):
        dev = self.get_selected()
        if not dev:
            return
        path = dev.get("path") or f"/dev/{dev.get('name')}"
        if is_system_device(dev):
            self.status_msg = f"ABORT: {path} is an OS system disk!"
            self.status_color = 3
            return

        code, out, err = run_cmd(f"sudo df-mount unblock {path}")
        if code == 0:
            self.status_msg = f"UNBLOCKED: {path} is now WRITABLE for raw disk cloning."
            self.status_color = 3
        else:
            self.status_msg = f"FAILED: {err or out}"
            self.status_color = 3
        self.refresh_devices()

    def action_unmount(self):
        dev = self.get_selected()
        if not dev:
            return
        path = dev.get("path") or f"/dev/{dev.get('name')}"
        code, out, err = run_cmd(f"sudo df-mount umount {path}")
        if code == 0:
            self.status_msg = f"UNMOUNTED: Flushed and unmounted {path} safely."
            self.status_color = 2
        else:
            self.status_msg = f"FAILED: {err or out}"
            self.status_color = 3
        self.refresh_devices()

    def launch_dfdisk(self):
        curses.endwin()
        os.system("sudo dfdisk")
        # Re-enter curses
        self.stdscr.clear()
        self.refresh_devices()

    def launch_nmtui(self):
        curses.endwin()
        os.system("nmtui")
        self.stdscr.clear()
        self.refresh_devices()

    def run(self):
        while True:
            self.draw()
            key = self.stdscr.getch()

            if key in [ord("q"), ord("Q"), 27]:  # 27 = ESC
                break
            elif key in [curses.KEY_UP, ord("k")]:
                if self.selected_idx > 0:
                    self.selected_idx -= 1
            elif key in [curses.KEY_DOWN, ord("j")]:
                if self.selected_idx < len(self.devices) - 1:
                    self.selected_idx += 1
            elif key in [ord("e"), ord("E")]:
                self.action_mount_evidence()
            elif key in [ord("t"), ord("T")]:
                self.action_mount_target()
            elif key in [ord("u"), ord("U")]:
                self.action_unblock_raw()
            elif key in [ord("x"), ord("X")]:
                self.action_unmount()
            elif key in [ord("d"), ord("D")]:
                self.launch_dfdisk()
            elif key in [ord("n"), ord("N")]:
                self.launch_nmtui()
            elif key in [ord("r"), ord("R")]:
                self.refresh_devices()
                self.status_msg = "Rescanned storage devices."
                self.status_color = 2


def main():
    curses.wrapper(lambda scr: DfMountTUI(scr).run())


if __name__ == "__main__":
    main()
