{ lib
, rustPlatform
, makeWrapper
, util-linux
, coreutils
}:

rustPlatform.buildRustPackage {
  pname = "dfmount";
  version = "0.1.0";

  src = lib.cleanSource ./.;

  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  nativeBuildInputs = [ makeWrapper ];

  postInstall = ''
    # Install companion CLI helper
    cp scripts/dfmount.sh $out/bin/dfmount-cli
    chmod +x $out/bin/dfmount-cli

    # Compatibility symlinks
    ln -s $out/bin/dfmount $out/bin/df-mount
    ln -s $out/bin/dfmount $out/bin/df-status
    ln -s $out/bin/dfmount $out/bin/df-unblock
    ln -s $out/bin/dfmount $out/bin/df-target
    ln -s $out/bin/dfmount $out/bin/df-umount

    wrapProgram $out/bin/dfmount \
      --prefix PATH : ${lib.makeBinPath [ util-linux coreutils ]}

    wrapProgram $out/bin/dfmount-cli \
      --prefix PATH : ${lib.makeBinPath [ util-linux coreutils ]}

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
