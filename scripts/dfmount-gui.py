#!/usr/bin/env python3
"""
df-mount-gui: Forensic Disk Mounter & Target Management Interface
Designed for df-nix Forensic Live OS.
"""

import sys
import os
import json
import subprocess

try:
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Gtk, Adw, Gio, GLib, Pango
    HAS_GTK = True
except Exception:
    HAS_GTK = False


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


def is_system_device(dev):
    mounts = dev.get("mountpoints") or []
    for m in mounts:
        if m in ["/", "/boot", "/nix", "[SWAP]"] or (m and m.startswith("/run")):
            return True
    for child in dev.get("children", []):
        if is_system_device(child):
            return True
    return False


if HAS_GTK:
    class DfMountApp(Adw.Application):
        def __init__(self):
            super().__init__(
                application_id="org.dfnix.dfmount",
                flags=Gio.ApplicationFlags.FLAGS_NONE
            )

        def do_activate(self):
            self.win = DfMountWindow(application=self)
            self.win.present()


    class DfMountWindow(Adw.ApplicationWindow):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.set_title("df-mount — Forensic Disk Manager")
            self.set_default_size(950, 620)

            # Main layout box
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
            self.set_content(box)

            # Header bar
            header = Adw.HeaderBar()
            box.append(header)

            title_widget = Adw.WindowTitle(
                title="Forensic Media & Target Manager",
                subtitle="Safely mount evidence (0 journal writes) or unblock targets for dfdisk"
            )
            header.set_title_widget(title_widget)

            # Refresh button
            btn_refresh = Gtk.Button(icon_name="view-refresh-symbolic")
            btn_refresh.set_tooltip_text("Refresh storage devices")
            btn_refresh.connect("clicked", lambda _: self.refresh_devices())
            header.pack_start(btn_refresh)

            # Launch dfdisk button
            btn_dfdisk = Gtk.Button(label="Launch dfdisk")
            btn_dfdisk.add_css_class("suggested-action")
            btn_dfdisk.set_tooltip_text("Open dfdisk forensic disk imager TUI")
            btn_dfdisk.connect("clicked", lambda _: self.launch_dfdisk())
            header.pack_end(btn_dfdisk)

            # Device list container
            scrolled = Gtk.ScrolledWindow()
            scrolled.set_vexpand(True)
            box.append(scrolled)

            self.clamp = Adw.Clamp()
            self.clamp.set_maximum_size(900)
            scrolled.set_child(self.clamp)

            self.list_box = Gtk.ListBox()
            self.list_box.set_selection_mode(Gtk.SelectionMode.NONE)
            self.list_box.add_css_class("boxed-list")
            self.clamp.set_child(self.list_box)

            # Status banner
            self.banner = Adw.Banner(title="")
            box.append(self.banner)

            self.refresh_devices()

        def refresh_devices(self):
            # Clear existing rows
            while True:
                row = self.list_box.get_row_at_index(0)
                if row is None:
                    break
                self.list_box.remove(row)

            devices = get_block_devices()
            if not devices:
                empty_row = Adw.ActionRow(title="No storage devices detected.")
                self.list_box.append(empty_row)
                return

            for dev in devices:
                self.add_device_rows(dev)

        def add_device_rows(self, dev, level=0):
            name = dev.get("name", "")
            path = dev.get("path", f"/dev/{name}")
            size = dev.get("size", "")
            ro = dev.get("ro", False)
            dev_type = dev.get("type", "")
            fstype = dev.get("fstype") or ""
            model = dev.get("model") or ""
            serial = dev.get("serial") or ""
            mounts = dev.get("mountpoints") or []
            mountpoint = ", ".join([m for m in mounts if m])
            is_sys = is_system_device(dev)

            row = Adw.ActionRow()
            indent = "    " * level
            display_title = f"{indent}{name} ({size})"
            if model:
                display_title += f" — {model}"
            if serial:
                display_title += f" [S/N: {serial}]"

            row.set_title(display_title)

            # Subtitle
            status_parts = []
            if is_sys:
                status_parts.append("⛔ SYSTEM DISK")
            elif ro:
                status_parts.append("🔒 READ-ONLY (LOCKED)")
            else:
                status_parts.append("💾 WRITEABLE (TARGET)")

            if fstype:
                status_parts.append(f"FS: {fstype}")
            if mountpoint:
                status_parts.append(f"Mounted at: {mountpoint}")

            row.set_subtitle(f"{indent}{' | '.join(status_parts)}")

            # Action buttons
            btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            btn_box.set_valign(Gtk.Align.CENTER)

            if is_sys:
                lbl = Gtk.Label(label="Protected")
                lbl.add_css_class("dim-label")
                btn_box.append(lbl)
            else:
                if mountpoint:
                    btn_umount = Gtk.Button(label="Unmount")
                    btn_umount.connect("clicked", lambda _, p=path: self.do_umount(p))
                    btn_box.append(btn_umount)
                else:
                    # Mount Evidence
                    btn_evid = Gtk.Button(label="🔒 Evidence")
                    btn_evid.set_tooltip_text("Mount write-blocked with zero journal replay")
                    btn_evid.connect("clicked", lambda _, p=path: self.do_mount_evidence(p))
                    btn_box.append(btn_evid)

                    # Mount Target
                    btn_target = Gtk.Button(label="💾 Target")
                    btn_target.set_tooltip_text("Mount writeable for dfdisk output")
                    btn_target.connect("clicked", lambda _, p=path: self.do_mount_target(p))
                    btn_box.append(btn_target)

                    # Unblock Raw Disk
                    if dev_type == "disk" and ro:
                        btn_unblock = Gtk.Button(label="🔓 Unblock")
                        btn_unblock.add_css_class("destructive-action")
                        btn_unblock.set_tooltip_text("Unblock raw block device for full drive cloning target")
                        btn_unblock.connect("clicked", lambda _, p=path: self.do_unblock(p))
                        btn_box.append(btn_unblock)

            row.add_suffix(btn_box)
            self.list_box.append(row)

            # Recurse for partitions
            for child in dev.get("children", []):
                self.add_device_rows(child, level=level + 1)

        def do_mount_evidence(self, path):
            code, out, err = run_cmd(f"sudo df-mount evidence {path}")
            self.show_result(code == 0, out or err)
            self.refresh_devices()

        def do_mount_target(self, path):
            code, out, err = run_cmd(f"sudo df-mount target {path}")
            self.show_result(code == 0, out or err)
            self.refresh_devices()

        def do_unblock(self, path):
            code, out, err = run_cmd(f"sudo df-mount unblock {path}")
            self.show_result(code == 0, out or err)
            self.refresh_devices()

        def do_umount(self, path):
            code, out, err = run_cmd(f"sudo df-mount umount {path}")
            self.show_result(code == 0, out or err)
            self.refresh_devices()

        def launch_dfdisk(self):
            subprocess.Popen(["kitty", "--title", "dfdisk - Forensic Imager", "-e", "sudo", "dfdisk"])

        def show_result(self, success, msg):
            self.banner.set_title(msg.splitlines()[-1] if msg else "Done")
            self.banner.set_revealed(True)
            GLib.timeout_add_seconds(4, lambda: self.banner.set_revealed(False))

    def main():
        app = DfMountApp()
        return app.run(sys.argv)

else:
    # CLI / Zenity fallback if GTK4 / Libadwaita is not loaded
    def main():
        print("GTK4 / Libadwaita not detected. Invoking df-mount CLI status:")
        subprocess.run(["df-mount", "status"])
        return 0

if __name__ == "__main__":
    sys.exit(main())
