{
  description = "Web SSL VPN";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    systems.url = "github:nix-systems/default";
  };

  outputs = { nixpkgs, systems, ... }:
    let
      eachSystem = nixpkgs.lib.genAttrs (import systems);
    in {
      devShells = eachSystem (system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in {
          default = pkgs.mkShell {
            nativeBuildInputs = with pkgs; [
              cargo
              rustc
              trunk
              binaryen
              lld
              wasm-bindgen-cli
              rustup
              openssl.bin
              curl
              zig
              cmake
              perl
              sudo
              pkg-config
              llvmPackages_latest.llvm
            ];

            RUSTUP_TOOLCHAIN = "stable";
            CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_LINKER = "${pkgs.lld}/bin/lld";

            buildInputs = with pkgs; [
              libxkbcommon
              vulkan-loader
              wayland
              wayland-protocols
              libGL
              libx11
              libxcursor
              libxrandr
              libxi
              libxcb
            ];

            LIBCLANG_PATH = "${pkgs.llvmPackages_latest.libclang}/lib";

            shellHook = ''
              export ZIG_CACHE_DIR="$PWD/.cache/zig"
              export XDG_CACHE_HOME="$PWD/.cache"

              export http_proxy="''${http_proxy:-http://127.0.0.1:7897}"
              export https_proxy="''${https_proxy:-http://127.0.0.1:7897}"

              # GUI libraries for iced desktop
              export LD_LIBRARY_PATH="${pkgs.libGL}/lib:${pkgs.libxkbcommon}/lib:${pkgs.libx11}/lib:${pkgs.libxcursor}/lib:${pkgs.libxrandr}/lib:${pkgs.libxi}/lib:${pkgs.libxcb}/lib:${pkgs.wayland}/lib:''${LD_LIBRARY_PATH:-}"

              if ! rustup toolchain list | grep -q nightly; then
                rustup toolchain install nightly
              fi
              if ! rustup +nightly component list --installed | grep -q rust-src; then
                rustup +nightly component add rust-src
              fi
            '';
          };
        });
    };
}
