const std = @import("std");

pub fn build(b: *std.Build) void {
    const certs_step  = b.step("certs",     "Generate CA + server SSL certificates");
    const trust_step  = b.step("trust",     "Generate certs/ca-bundle.crt for SSL trust");
    const ca_step     = b.step("install-ca","Install CA cert to system trust store (sudo)");
    const trunk_step  = b.step("trunk",     "Build iced WASM frontend (debug)");
    const check_step  = b.step("check",     "cargo check server + web + ebpf (fast compile check)");
    const test_step   = b.step("test",      "cargo test all packages");
    const wasm_step   = b.step("wasm",      "Full frontend: certs + trust + trunk");
    const run_step    = b.step("run",       "Build all + start server (debug, eBPF optional)");
    const ebpf_build  = b.step("ebpf-build","Build eBPF BPF program (bpfel-unknown-none)");
    const ebpf_run    = b.step("ebpf-run",  "Build eBPF + trunk + server, run with sudo (BPF attach)");
    const desktop_step = b.step("desktop",   "Build native iced desktop app");
    const desktop_run  = b.step("desktop-run","Build + run native desktop app");
    const release_step = b.step("release",  "Release build: certs + trunk --release + cargo build --release");

    // ── Certificates ──────────────────────────────────

    const mkdir_certs = b.addSystemCommand(&.{ "mkdir", "-p", "certs" });

    const gen_certs = b.addSystemCommand(&.{
        "bash", "-c",
        \\if [ -f certs/ca.crt ] && [ -f certs/ca.key ] &&
        \\   [ -f certs/server.crt ] && [ -f certs/server.key ]; then
        \\  echo "Certificates already exist, skipping generation"
        \\  exit 0
        \\fi
        \\echo "Generating CA certificate..."
        \\openssl genrsa -out certs/ca.key 4096 2>/dev/null || true
        \\openssl req -x509 -new -nodes -key certs/ca.key -sha256 -days 3650 \
        \\  -out certs/ca.crt -subj "/CN=Web SSL VPN CA" 2>/dev/null || true
        \\echo "Generating server certificate..."
        \\openssl genrsa -out certs/server.key 2048 2>/dev/null || true
        \\openssl req -new -key certs/server.key -out certs/server.csr \
        \\  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null || true
        \\openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key \
        \\  -CAcreateserial -out certs/server.crt -days 365 -sha256 \
        \\  -extfile certs/ext.cnf 2>/dev/null || true
        \\rm -f certs/server.csr
        \\echo "Certificates ready"
    });
    gen_certs.step.dependOn(&mkdir_certs.step);
    certs_step.dependOn(&gen_certs.step);

    // ── Trust bundle ──────────────────────────────────

    const gen_bundle = b.addSystemCommand(&.{
        "bash", "-c",
        \\for f in /etc/ssl/certs/ca-bundle.crt /etc/ssl/certs/ca-certificates.crt; do
        \\  if [ -f "$f" ]; then cat "$f" certs/ca.crt > certs/ca-bundle.crt && echo "Created certs/ca-bundle.crt (system + CA)" && exit 0; fi
        \\done
        \\cp certs/ca.crt certs/ca-bundle.crt && echo "Created certs/ca-bundle.crt (CA only)"
    });
    gen_bundle.step.dependOn(&gen_certs.step);
    trust_step.dependOn(&gen_bundle.step);

    // ── Install CA ────────────────────────────────────

    const inst = b.addSystemCommand(&.{
        "bash", "-c",
        \\if [ -f /etc/debian_version ]; then
        \\  sudo cp certs/ca.crt /usr/local/share/ca-certificates/web-ssl-vpn.crt && sudo update-ca-certificates && echo "✓ CA installed (Debian/Ubuntu)"
        \\elif [ -f /etc/fedora-release ] || [ -f /etc/redhat-release ]; then
        \\  sudo cp certs/ca.crt /etc/pki/ca-trust/source/anchors/web-ssl-vpn.crt && sudo update-ca-trust && echo "✓ CA installed"
        \\elif command -v trust &>/dev/null; then
        \\  sudo trust anchor certs/ca.crt && echo "✓ CA installed (Arch)"
        \\elif [ -f /etc/nixos ]; then
        \\  echo "NixOS: add to security.pki.certificateFiles: $(readlink -f certs/ca.crt)"
        \\else
        \\  echo "Unknown distro. Manually trust certs/ca.crt"
        \\fi
    });
    inst.step.dependOn(&gen_certs.step);
    ca_step.dependOn(&inst.step);

    // ── Trunk (debug) ─────────────────────────────────

    const trunk_cmd = b.addSystemCommand(&.{ "trunk", "build" });
    trunk_cmd.setEnvironmentVariable("NO_COLOR", "true");
    trunk_cmd.setCwd(.{ .cwd_relative = "web" });

    trunk_step.dependOn(&trunk_cmd.step);
    wasm_step.dependOn(&gen_certs.step);
    wasm_step.dependOn(&gen_bundle.step);
    wasm_step.dependOn(&trunk_cmd.step);

    // ── Check ─────────────────────────────────────────

    const check_server = b.addSystemCommand(&.{ "cargo", "check", "-p", "server" });
    check_server.setCwd(.{ .cwd_relative = "." });

    const check_web = b.addSystemCommand(&.{ "cargo", "check", "--target", "wasm32-unknown-unknown", "-p", "web" });
    check_web.setCwd(.{ .cwd_relative = "." });
    check_web.step.dependOn(&check_server.step);

    const check_ebpf = b.addSystemCommand(&.{
        "bash", "-c",
        \\export RUSTUP_TOOLCHAIN=nightly
        \\export PATH=$(echo "$PATH" | tr ':' '\n' | grep -v 'cargo-' | grep -v 'rustc-wrapper' | tr '\n' ':')
        \\rustup run nightly cargo check -p ebpf --target bpfel-unknown-none -Z build-std=core
    });
    check_ebpf.setCwd(.{ .cwd_relative = "." });
    check_web.step.dependOn(&check_ebpf.step);

    check_step.dependOn(&check_web.step);

    // ── Test ──────────────────────────────────────────

    const test_server = b.addSystemCommand(&.{ "cargo", "test", "-p", "server" });
    test_server.setCwd(.{ .cwd_relative = "." });

    test_step.dependOn(&test_server.step);

    // ── eBPF Build ────────────────────────────────────

    const ebpf_build_cmd = b.addSystemCommand(&.{
        "bash", "-c",
        \\export RUSTUP_TOOLCHAIN=nightly
        \\export PATH=$(echo "$PATH" | tr ':' '\n' | grep -v 'cargo-' | grep -v 'rustc-wrapper' | tr '\n' ':')
        \\rustup run nightly cargo build -p ebpf --target bpfel-unknown-none --release -Z build-std=core
        \\if [ -f target/bpfel-unknown-none/release/ebpf ]; then
        \\  echo "eBPF binary ready"
        \\else
        \\  echo "eBPF build failed: no binary at target/bpfel-unknown-none/release/ebpf"
        \\  exit 1
        \\fi
    });
    ebpf_build_cmd.setCwd(.{ .cwd_relative = "." });

    ebpf_build.dependOn(&ebpf_build_cmd.step);

    // ── Server build (shared) ─────────────────────────

    const build_server = b.addSystemCommand(&.{ "cargo", "build", "-p", "server" });
    build_server.setCwd(.{ .cwd_relative = "." });
    build_server.step.dependOn(&gen_certs.step);
    build_server.step.dependOn(&gen_bundle.step);
    build_server.step.dependOn(&trunk_cmd.step);

    // ── Run (debug, no eBPF) ──────────────────────────

    const run_cmd = b.addSystemCommand(&.{ "cargo", "run", "-p", "server" });
    run_cmd.setCwd(.{ .cwd_relative = "." });
    run_cmd.step.dependOn(&build_server.step);

    run_step.dependOn(&run_cmd.step);

    // ── eBPF Run (with sudo for TC attach) ────────────

    const build_ebpf_server = b.addSystemCommand(&.{ "cargo", "build", "-p", "server" });
    build_ebpf_server.setCwd(.{ .cwd_relative = "." });
    build_ebpf_server.step.dependOn(&gen_certs.step);
    build_ebpf_server.step.dependOn(&gen_bundle.step);
    build_ebpf_server.step.dependOn(&trunk_cmd.step);
    build_ebpf_server.step.dependOn(&ebpf_build_cmd.step);

    const ebpf_run_cmd = b.addSystemCommand(&.{
        "bash", "-c",
        \\echo "=== eBPF mode: TC attach requires root ==="
        \\SYSUDO=""
        \\for p in /run/wrappers/bin/sudo /usr/bin/sudo /bin/sudo; do
        \\  if [ -x "$p" ] && [ -u "$p" ]; then SYSUDO="$p"; break; fi
        \\done
        \\if [ -z "$SYSUDO" ]; then
        \\  echo "ebpf-run: no suid sudo found. Try running outside nix develop, or run manually with sudo."
        \\  exit 1
        \\fi
        \\if [ "$(id -u)" = "0" ]; then
        \\  exec ./target/debug/server
        \\fi
        \\if ! "$SYSUDO" -n true 2>/dev/null; then
        \\  echo "Password required for eBPF privilege escalation."
        \\fi
        \\"$SYSUDO" -v || { echo "sudo: authentication failed"; exit 1; }
        \\exec "$SYSUDO" ./target/debug/server
    });
    ebpf_run_cmd.setCwd(.{ .cwd_relative = "." });
    ebpf_run_cmd.step.dependOn(&build_ebpf_server.step);

    ebpf_run.dependOn(&ebpf_run_cmd.step);

    // ── Release ───────────────────────────────────────

    const trunk_release = b.addSystemCommand(&.{ "trunk", "build", "--release" });
    trunk_release.setEnvironmentVariable("NO_COLOR", "true");
    trunk_release.setCwd(.{ .cwd_relative = "web" });
    trunk_release.step.dependOn(&gen_certs.step);

    const build_release = b.addSystemCommand(&.{
        "cargo", "build", "--release", "-p", "server",
    });
    build_release.setCwd(.{ .cwd_relative = "." });
    build_release.step.dependOn(&trunk_release.step);
    build_release.step.dependOn(&gen_bundle.step);

    release_step.dependOn(&build_release.step);

    // ── Desktop ────────────────────────────────────────

    const build_desktop = b.addSystemCommand(&.{
        "cargo", "build", "-p", "desktop",
    });
    build_desktop.setCwd(.{ .cwd_relative = "." });

    desktop_step.dependOn(&build_desktop.step);

    const build_server_for_desktop = b.addSystemCommand(&.{ "cargo", "build", "-p", "server" });
    build_server_for_desktop.setCwd(.{ .cwd_relative = "." });
    build_server_for_desktop.step.dependOn(&gen_certs.step);
    build_server_for_desktop.step.dependOn(&gen_bundle.step);

    const run_desktop = b.addSystemCommand(&.{
        "bash", "-c",
        \\if [ -z "$VPN_SERVER" ]; then
        \\  export VPN_SERVER="https://localhost:8443"
        \\  if ! ss -tlnp 2>/dev/null | grep -q ':8443 '; then
        \\    echo "Starting VPN server on :8443..."
        \\    rm -f vpn.db
        \\    ./target/debug/server &
        \\    SERVER_PID=$!
        \\    for i in $(seq 1 20); do
        \\      sleep 0.5
        \\      if ss -tlnp 2>/dev/null | grep -q ':8443 '; then break; fi
        \\    done
        \\    echo "VPN server ready"
        \\  fi
        \\fi
        \\echo "Desktop → $VPN_SERVER"
        \\./target/debug/desktop
        \\if [ -n "${SERVER_PID:-}" ]; then
        \\  kill $SERVER_PID 2>/dev/null
        \\  echo "VPN server stopped"
        \\fi
    });
    run_desktop.setCwd(.{ .cwd_relative = "." });
    run_desktop.step.dependOn(&build_desktop.step);
    run_desktop.step.dependOn(&build_server_for_desktop.step);

    desktop_run.dependOn(&run_desktop.step);
}
