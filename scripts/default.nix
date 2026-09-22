{ lib
, stdenv
, makeWrapper
, util-linux
, gawk
, gnugrep
, coreutils
, jq
, python3
, wrapGAppsHook4
, gtk4
, libadwaita
, gobject-introspection
}:

let
  pythonEnv = python3.withPackages (ps: with ps; [
    pygobject3
  ]);
in
stdenv.mkDerivation rec {
  pname = "dfmount";
  version = "0.2.0";

  src = ./.;

  nativeBuildInputs = [
    makeWrapper
    wrapGAppsHook4
    gobject-introspection
  ];

  buildInputs = [
    gtk4
    libadwaita
    pythonEnv
  ];

  installPhase = ''
    runHook preInstall

    mkdir -p $out/bin $out/share/applications

    # 1. Install primary TUI (curses, zero external deps)
    cp dfmount-tui.py $out/bin/dfmount
    chmod +x $out/bin/dfmount

    wrapProgram $out/bin/dfmount \
      --prefix PATH : ${lib.makeBinPath [
        util-linux
        gawk
        gnugrep
        coreutils
        jq
      ]}:$out/bin

    # 2. Install CLI script
    cp dfmount.sh $out/bin/dfmount-cli
    chmod +x $out/bin/dfmount-cli

    wrapProgram $out/bin/dfmount-cli \
      --prefix PATH : ${lib.makeBinPath [
        util-linux
        gawk
        gnugrep
        coreutils
        jq
      ]}

    # Compatibility symlinks
    ln -s $out/bin/dfmount-cli $out/bin/df-mount
    ln -s $out/bin/dfmount-cli $out/bin/df-status
    ln -s $out/bin/dfmount-cli $out/bin/df-unblock
    ln -s $out/bin/dfmount-cli $out/bin/df-target
    ln -s $out/bin/dfmount-cli $out/bin/df-umount

    # 3. Install GUI wrapper
    cp dfmount-gui.py $out/bin/dfmount-gui
    chmod +x $out/bin/dfmount-gui

    wrapProgram $out/bin/dfmount-gui \
      --prefix PATH : ${lib.makeBinPath [
        util-linux
        gawk
        gnugrep
        coreutils
      ]}:$out/bin \
      --prefix PYTHONPATH : "${pythonEnv}/${pythonEnv.sitePackages}"

    # Desktop entry for dfmount TUI
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

    runHook postInstall
  '';

  meta = with lib; {
    description = "Forensic disk mounting & target management suite for df-nix";
    license = licenses.mit;
    platforms = platforms.linux;
    maintainers = [ ];
    mainProgram = "dfmount";
  };
}
