use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let bpf_manifest = manifest_dir.join("ebpf_programs/Cargo.toml");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target_dir = out_dir.join("bpf-build");

    // Match the host arch so BPF code can use #[cfg(bpf_target_arch = "...")]
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "x86_64".to_string());
    let rustflags =
        format!("--cfg=bpf_target_arch=\"{arch}\"\x1f-Cdebuginfo=2\x1f-Clink-arg=--btf");

    let status = Command::new("rustup")
        .args([
            "run",
            "nightly",
            "cargo",
            "build",
            "--manifest-path",
            bpf_manifest.to_str().unwrap(),
            "-Z",
            "build-std=core",
            "--bins",
            "--release",
            "--target",
            "bpfel-unknown-none",
            "--target-dir",
            target_dir.to_str().unwrap(),
        ])
        .env_remove("RUSTC")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env("CARGO_ENCODED_RUSTFLAGS", &rustflags)
        .status()
        .expect("failed to invoke cargo for BPF build");

    assert!(status.success(), "BPF programs build failed");

    let src = target_dir.join("bpfel-unknown-none/release/ebpf_programs");
    let dst = out_dir.join("ebpf_programs");
    std::fs::copy(&src, &dst).expect("failed to copy BPF binary to OUT_DIR");

    println!("cargo:rerun-if-changed=ebpf_programs/src");
    println!("cargo:rerun-if-changed=ebpf_programs/Cargo.toml");
}
