use std::process::Command;

fn main() {
    let path_var = std::env::var("PATH").unwrap_or_default();
    let filtered_path: Vec<&str> = path_var
        .split(':')
        .filter(|p| !p.contains("cargo-") && !p.contains("rustc-wrapper"))
        .collect();
    let clean_path = filtered_path.join(":");

    let status = Command::new("rustup")
        .env("RUSTUP_TOOLCHAIN", "nightly")
        .env("PATH", &clean_path)
        .args([
            "run", "nightly", "cargo",
            "build",
            "--package", "ebpf",
            "--target", "bpfel-unknown-none",
            "--profile", "release",
            "-Z", "build-std=core",
        ])
        .status();

    match status {
        Ok(s) if s.success() => {
            let binary = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../target/bpfel-unknown-none/release/ebpf");
            if binary.exists() {
                println!("cargo:rustc-cfg=ebpf_available");
            } else {
                println!("cargo:warning=eBPF binary not found at {}", binary.display());
            }
            println!("cargo:rerun-if-changed=../ebpf/src/lib.rs");
        }
        _ => {
            println!("cargo:warning=eBPF build skipped (bpf target not available)");
        }
    }
}
