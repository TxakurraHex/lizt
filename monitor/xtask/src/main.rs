use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

const BIN_DIR: &str = "/usr/bin";
const CONF_DIR: &str = "/etc/lizt";
const LOG_DIR: &str = "/var/log/lizt";
const SYSTEMD_DIR: &str = "/etc/systemd/system";

// Binary resolved from CARGO_MANIFEST_DIR at runtime - works regardless of build location
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a parent directory")
        .to_owned()
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let release = args.iter().any(|a| a == "--release");
    let task = args
        .iter()
        .skip(1)
        .find(|a| *a != "--release")
        .map(String::as_str);
    match task {
        Some("install") => install(release),
        Some("uninstall") => uninstall(),
        _ => {
            eprintln!("Usage: cargo xtask <install|uninstall> [--release]");
            std::process::exit(1);
        }
    }
}

fn install(release: bool) -> Result<()> {
    require_root()?;

    let root = workspace_root();

    // 1. Binary
    let profile = if release { "release" } else { "debug" };
    let binary_src = root.join(format!("target/{profile}/lizt_monitord"));
    if !binary_src.exists() {
        bail!(
            "Binary not found at {}. Run `cargo build{} -p lizt_ebpf` first.",
            binary_src.display(),
            if release { " --release" } else { "" }
        );
    }
    let binary_dst = Path::new(BIN_DIR).join("lizt_monitord");
    fs::copy(&binary_src, &binary_dst)
        .with_context(|| format!("Failed to copy binary to {}", binary_dst.display()))?;
    set_permissions(&binary_dst, 0o755)?;
    println!("Installed: {}", binary_dst.display());

    // 2. Conf + Log directories
    create_dir_all(CONF_DIR)?;
    create_dir_all(LOG_DIR)?;

    // 3. log4rs config
    let log4rs_src = root.join("conf/monitord_log4rs.yaml");
    let log4rs_dst = Path::new(CONF_DIR).join("monitord_log4rs.yaml");
    copy_file_if_changed(&log4rs_src, &log4rs_dst)?;

    // 4. env file
    let env_dst = Path::new(CONF_DIR).join("env");
    if !env_dst.exists() {
        let env_example = root.join("conf/env_example");
        fs::copy(&env_example, &env_dst)
            .with_context(|| format!("Failed to create {}", env_dst.display()))?;
        set_permissions(&env_dst, 0o600)?;
        println!(
            "Created {} from env.example and update with real DATABASE_URL and NVD_API_KEY",
            env_dst.display()
        );
    } else {
        println!("Skipping env file (already exists): {}", env_dst.display());
    }

    // 5. systemd unit
    let unit_src = root.join("conf/lizt_monitord.service");
    let unit_dst = Path::new(SYSTEMD_DIR).join("lizt_monitord.service");
    copy_file_if_changed(&unit_src, &unit_dst)?;
    set_permissions(&unit_dst, 0o644)?;

    // 6. systemctl daemon-reload
    run("systemctl", &["daemon-reload"])?;
    println!("Done. Run: systemctl enable --now lizt_monitord to start monitor daemon");

    Ok(())
}

fn uninstall() -> Result<()> {
    require_root()?;

    run("systemctl", &["disable", "--now", "lizt_monitord"]).ok();

    for path in &[
        "/usr/bin/lizt_monitord",
        "/etc/systemd/system/lizt_monitord.service",
        "/etc/lizt/list_monitord_log4rs.yaml",
    ] {
        if Path::new(path).exists() {
            fs::remove_file(path).with_context(|| format!("Failed to remove {path}"))?;
            println!("Removed: {path}");
        }
    }

    println!("Note: did not remove /etc/lizt/env and /var/log/lizt");

    run("systemctl", &["daemon-reload"])?;

    Ok(())
}

fn require_root() -> Result<()> {
    let output = Command::new("id").arg("-u").output()?;
    let uid: u32 = String::from_utf8_lossy(&output.stdout).trim().parse()?;
    if uid != 0 {
        bail!("This command must be run as root (sudo cargo xtask install)");
    }
    Ok(())
}

fn create_dir_all(path: &str) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("Failed to create directory {path}"))
}

fn set_permissions(path: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("Failed to set permissions on {}", path.display()))
}

fn copy_file_if_changed(src: &Path, dst: &Path) -> Result<()> {
    if !src.exists() {
        bail!("Source file not found: {}", src.display());
    }
    fs::copy(src, dst)
        .with_context(|| format!("Failed to copy {} -> {}", src.display(), dst.display()))?;
    println!("Installed: {}", dst.display());
    Ok(())
}

fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(cmd)
        .args(args)
        .status()
        .with_context(|| format!("Failed to run `{cmd}`"))?;
    if !status.success() {
        bail!("`{cmd} {}` exited with {status}", args.join(" "));
    }
    Ok(())
}
