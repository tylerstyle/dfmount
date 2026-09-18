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
    wrapProgram $out/bin/dfmount \
      --prefix PATH : ${lib.makeBinPath [ util-linux coreutils ]}
  '';

  meta = with lib; {
    description = "Modern forensic storage mounter & target unblocker TUI";
    homepage = "https://github.com/tylerstyle/dfmount";
    license = with licenses; [ mit asl20 ];
    mainProgram = "dfmount";
    platforms = platforms.linux;
  };
}
