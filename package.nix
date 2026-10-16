{ lib
, rustPlatform
, runCommand
, makeWrapper
, util-linux
, coreutils
, cryptsetup
, mdadm
, lvm2
  # dfcore is a sibling path dependency (../dfcore); flakes pass their input
, dfcoreSrc ? ../dfcore
}:

let
  clean = src: lib.cleanSourceWith {
    filter = path: type: baseNameOf path != "target";
    src = lib.cleanSource src;
  };
  # Lay out the sources as in ~/git so `path = "../dfcore"` resolves
  src = runCommand "dfmount-src" { } ''
    mkdir -p $out
    cp -r ${clean ./.} $out/dfmount
    cp -r ${clean dfcoreSrc} $out/dfcore
    chmod -R u+w $out
  '';
in
rustPlatform.buildRustPackage {
  pname = "dfmount";
  version = "0.1.1";

  inherit src;
  sourceRoot = "dfmount-src/dfmount";

  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  nativeBuildInputs = [ makeWrapper ];

  postInstall = ''
    # Compatibility symlinks (dfmount-cli used to be a separate shell script;
    # it now runs the Rust binary so every entry point shares its safety checks)
    ln -s $out/bin/dfmount $out/bin/dfmount-cli
    ln -s $out/bin/dfmount $out/bin/df-mount
    ln -s $out/bin/dfmount $out/bin/df-status
    ln -s $out/bin/dfmount $out/bin/df-unblock
    ln -s $out/bin/dfmount $out/bin/df-target
    ln -s $out/bin/dfmount $out/bin/df-umount

    wrapProgram $out/bin/dfmount \
      --prefix PATH : ${lib.makeBinPath [ util-linux coreutils cryptsetup mdadm lvm2 ]}
    # zpool/zfs come from the system: they must match its kernel module

    # Desktop launcher entry
    mkdir -p $out/share/applications
    cat > $out/share/applications/dfmount.desktop <<EOF
[Desktop Entry]
Version=1.0
Name=dfmount Forensic Storage TUI
GenericName=Forensic Disk Mounter
Comment=Mount evidence write-blocked with zero journal replay or unblock target drives
Exec=kitty --title "dfmount - Forensic Storage Manager" sudo dfmount
Icon=drive-harddisk-system
Terminal=false
Type=Application
Categories=System;Forensics;Utility;
Keywords=forensics;mount;writeblock;target;dfdisk;
EOF
  '';

  meta = with lib; {
    description = "Modern forensic storage mounter & target unblocker TUI";
    homepage = "https://github.com/tylerstyle/dfmount";
    license = with licenses; [ mit asl20 ];
    mainProgram = "dfmount";
    platforms = platforms.linux;
  };
}
