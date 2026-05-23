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
        .env("RUSTFLAGS", "--emit=obj")
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
            let deps_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../target/bpfel-unknown-none/release/deps");
            if let Ok(entries) = std::fs::read_dir(&deps_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().map_or(false, |e| e == "o") {
                        let dest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                            .join("../target/bpfel-unknown-none/release/ebpf");
                        let _ = std::fs::copy(&path, &dest);
                        break;
                    }
                }
            }
            println!("cargo:rustc-cfg=ebpf_available");
            println!("cargo:rerun-if-changed=../ebpf/src/lib.rs");
        }
        _ => {
            println!("cargo:warning=eBPF build skipped (bpf target not available)");
        }
    }
}
