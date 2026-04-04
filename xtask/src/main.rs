use std::env;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

const BIN_DIR: &str = "/usr/bin";
const CONF_DIR: &str = "/etc/lizt";
const LOG_DIR: &str = "/var/log/lizt";
const SYSTEMD_DIR: &str = "/etc/systemd/system";
const NGINX_SITES_AVAIL: &str = "/etc/nginx/sites-available";
const NGINX_SITES_ENABLED: &str = "/etc/nginx/sites-enabled";
const NGINX_SSL_DIR: &str = "/etc/nginx/ssl";
const NGINX_HTPASSWD: &str = "/etc/nginx/.lizt_htpasswd";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a parent directory")
        .to_owned()
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let release = args.iter().any(|a| a == "--release");
    let positional: Vec<&str> = args
        .iter()
        .skip(1)
        .filter(|a| *a != "--release")
        .map(String::as_str)
        .collect();

    match positional.as_slice() {
        ["install"] => install_all(release),
        ["install", "cli"] => install_cli(release),
        ["install", "web"] => install_web(release),
        ["install", "monitor"] => install_monitor(release),
        ["uninstall"] => uninstall_all(),
        ["uninstall", "cli"] => uninstall_cli(),
        ["uninstall", "web"] => uninstall_web(),
        ["uninstall", "monitor"] => uninstall_monitor(),
        _ => {
            eprintln!("Usage: cargo xtask <install|uninstall> <cli|web|monitor> [--release]");
            std::process::exit(1);
        }
    }
}

// ── install ───────────────────────────────────────────────────────────────────

fn install_all(release: bool) -> Result<()> {
    install_cli(release)?;
    install_web(release)?;
    install_monitor(release)?;
    Ok(())
}

fn install_cli(release: bool) -> Result<()> {
    require_root()?;
    let root = workspace_root();

    install_binary(&root, profile(release), "lizt-cli")?;
    create_dir_all(CONF_DIR)?;
    create_dir_all(LOG_DIR)?;
    copy_conf(&root.join("conf/log4rs.yaml"), CONF_DIR, "cli_log4rs.yaml")?;
    install_env_if_missing(&root.join("monitor/conf/env.example"))?;

    println!("Done. Run: lizt-cli --help");
    Ok(())
}

fn install_web(release: bool) -> Result<()> {
    require_root()?;
    let root = workspace_root();

    install_binary(&root, profile(release), "lizt")?;
    ensure_lizt_user()?;
    setup_log_dir()?;
    install_env_web()?;
    copy_conf(
        &root.join("scanner/web/conf/log4rs.yaml"),
        CONF_DIR,
        "log4rs.yaml",
    )?;
    install_tls_cert()?;
    install_htpasswd()?;
    install_nginx(&root)?;
    install_migrations(&root)?;
    install_systemd_unit(&root.join("scanner/web/conf/lizt.service"))?;
    run("systemctl", &["enable", "--now", "lizt"])?;
    run("systemctl", &["reload", "nginx"])?;

    println!("\nDone. Dashboard: https://<your-public-ip>  (self-signed cert warning expected)");
    Ok(())
}

fn install_monitor(release: bool) -> Result<()> {
    require_root()?;
    let root = workspace_root();

    // monitor is a separate workspace — its target dir sits under monitor/
    let binary_src = root.join(format!("monitor/target/{}/lizt_monitord", profile(release)));
    check_binary(&binary_src, release, "lizt_ebpf")?;
    install_binary_from(&binary_src, "lizt_monitord")?;

    ensure_lizt_user()?;
    setup_log_dir()?;
    copy_conf(
        &root.join("monitor/conf/monitord_log4rs.yaml"),
        CONF_DIR,
        "monitord_log4rs.yaml",
    )?;
    install_env_if_missing(&root.join("monitor/conf/env.example"))?;
    install_systemd_unit(&root.join("monitor/conf/lizt_monitord.service"))?;
    run("systemctl", &["enable", "--now", "lizt_monitord"])?;

    println!("Done. Check `symbol_observations` table to view any captured symbol probes.");
    Ok(())
}

// ── uninstall ─────────────────────────────────────────────────────────────────

fn uninstall_all() -> Result<()> {
    uninstall_cli()?;
    uninstall_web()?;
    uninstall_monitor()?;
    Ok(())
}

fn uninstall_cli() -> Result<()> {
    require_root()?;
    remove_files(&["/usr/bin/lizt-cli", "/etc/lizt/cli_log4rs.yaml"])?;
    println!("Note: did not remove /etc/lizt/env or /var/log/lizt");
    Ok(())
}

fn uninstall_web() -> Result<()> {
    require_root()?;
    run("systemctl", &["disable", "--now", "lizt"]).ok();
    remove_files(&[
        "/usr/bin/lizt",
        "/etc/systemd/system/lizt.service",
        "/etc/lizt/log4rs.yaml",
        "/etc/nginx/sites-enabled/lizt",
        "/etc/nginx/sites-available/lizt",
    ])?;
    run("systemctl", &["daemon-reload"])?;
    run("systemctl", &["reload", "nginx"]).ok();
    println!("Note: did not remove /etc/lizt/env, /var/log/lizt, TLS certs, or htpasswd");
    Ok(())
}

fn uninstall_monitor() -> Result<()> {
    require_root()?;
    run("systemctl", &["disable", "--now", "lizt_monitord"]).ok();
    remove_files(&[
        "/usr/bin/lizt_monitord",
        "/etc/systemd/system/lizt_monitord.service",
        "/etc/lizt/monitord_log4rs.yaml",
    ])?;
    run("systemctl", &["daemon-reload"])?;
    println!("Note: did not remove /etc/lizt/env or /var/log/lizt");
    Ok(())
}

// ── shared steps ──────────────────────────────────────────────────────────────

fn ensure_lizt_user() -> Result<()> {
    if !Command::new("id").arg("lizt").output()?.status.success() {
        run(
            "useradd",
            &[
                "--system",
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                "lizt",
            ],
        )?;
        println!("Created system user: lizt");
    }
    Ok(())
}

fn setup_log_dir() -> Result<()> {
    create_dir_all(LOG_DIR)?;
    run("chown", &["lizt:lizt", LOG_DIR])
}

fn install_env_if_missing(example: &Path) -> Result<()> {
    let dst = Path::new(CONF_DIR).join("env");
    if !dst.exists() {
        fs::copy(example, &dst).with_context(|| format!("Failed to create {}", dst.display()))?;
        set_permissions(&dst, 0o600)?;
        println!(
            "Created {}, update DATABASE_URL and NVD_API_KEY",
            dst.display()
        );
    } else {
        println!("Skipping env file (already exists): {}", dst.display());
    }
    Ok(())
}

fn install_env_web() -> Result<()> {
    let dst = Path::new(CONF_DIR).join("env");
    if !dst.exists() {
        fs::write(
            &dst,
            "DATABASE_URL=postgresql://user:password@localhost/lizt\nLIZT_WEB_PORT=8080\n# NVD_API_KEY=\n",
        )?;
        set_permissions(&dst, 0o600)?;
        println!(
            "Created {}, edit DATABASE_URL and NVD_API_KEY",
            dst.display()
        );
    } else {
        let contents = fs::read_to_string(&dst)?;
        if !contents.contains("LIZT_WEB_PORT") {
            let mut f = fs::OpenOptions::new().append(true).open(&dst)?;
            writeln!(f, "LIZT_WEB_PORT=8080")?;
            println!("Appended LIZT_WEB_PORT to existing env file");
        } else {
            println!("Skipping env file (already exists): {}", dst.display());
        }
    }
    Ok(())
}

fn install_tls_cert() -> Result<()> {
    create_dir_all(NGINX_SSL_DIR)?;
    if !Path::new(NGINX_SSL_DIR).join("lizt.crt").exists() {
        run(
            "openssl",
            &[
                "req",
                "-x509",
                "-nodes",
                "-days",
                "365",
                "-newkey",
                "rsa:2048",
                "-keyout",
                &format!("{NGINX_SSL_DIR}/lizt.key"),
                "-out",
                &format!("{NGINX_SSL_DIR}/lizt.crt"),
                "-subj",
                "/CN=lizt-dashboard",
            ],
        )?;
        println!("Generated self-signed TLS cert: {NGINX_SSL_DIR}/lizt.crt");
    } else {
        println!("TLS cert already exists, skipping");
    }
    Ok(())
}

fn install_htpasswd() -> Result<()> {
    if Path::new(NGINX_HTPASSWD).exists() {
        println!("htpasswd file already exists, skipping");
        return Ok(());
    }
    if !Command::new("which")
        .arg("htpasswd")
        .output()?
        .status
        .success()
    {
        run("apt-get", &["install", "-y", "-q", "apache2-utils"])?;
    }
    println!("\nCreate a dashboard login:");
    print!("  Username: ");
    std::io::stdout().flush()?;
    let mut username = String::new();
    std::io::stdin().read_line(&mut username)?;
    Command::new("htpasswd")
        .args(["-c", NGINX_HTPASSWD, username.trim()])
        .status()
        .context("Failed to run htpasswd")?;
    println!("Created {NGINX_HTPASSWD}");
    Ok(())
}

fn install_nginx(root: &Path) -> Result<()> {
    let avail = Path::new(NGINX_SITES_AVAIL).join("lizt");
    copy_file_if_changed(&root.join("scanner/web/conf/lizt_nginx.conf"), &avail)?;
    let enabled = Path::new(NGINX_SITES_ENABLED).join("lizt");
    if !enabled.exists() {
        std::os::unix::fs::symlink(&avail, &enabled)?;
    }
    let default = Path::new(NGINX_SITES_ENABLED).join("default");
    if default.exists() {
        fs::remove_file(&default)?;
    }
    run("nginx", &["-t"])?;
    println!("nginx config installed and validated");
    Ok(())
}

fn install_migrations(root: &Path) -> Result<()> {
    let dst = Path::new(CONF_DIR).join("migrations");
    if dst.exists() {
        fs::remove_dir_all(&dst)?;
    }
    copy_dir_all(&root.join("migrations"), &dst)?;
    println!("Installed migrations to {}", dst.display());
    Ok(())
}

fn install_systemd_unit(src: &Path) -> Result<()> {
    let dst = Path::new(SYSTEMD_DIR).join(src.file_name().expect("unit file has a name"));
    copy_file_if_changed(src, &dst)?;
    set_permissions(&dst, 0o644)?;
    run("systemctl", &["daemon-reload"])
}

fn profile(release: bool) -> &'static str {
    if release { "release" } else { "debug" }
}

/// Install a scanner workspace binary (lives under target/).
fn install_binary(root: &Path, profile: &str, name: &str) -> Result<()> {
    let src = root.join(format!("target/{profile}/{name}"));
    check_binary(&src, profile == "release", name)?;
    install_binary_from(&src, name)
}

fn install_binary_from(src: &Path, name: &str) -> Result<()> {
    let dst = Path::new(BIN_DIR).join(name);
    fs::copy(src, &dst).with_context(|| format!("Failed to copy binary to {}", dst.display()))?;
    set_permissions(&dst, 0o755)?;
    println!("Installed: {}", dst.display());
    Ok(())
}

fn check_binary(path: &Path, release: bool, package: &str) -> Result<()> {
    if !path.exists() {
        bail!(
            "Binary not found at {}. Run `cargo build{} -p {package}` first.",
            path.display(),
            if release { " --release" } else { "" }
        );
    }
    Ok(())
}

/// Copy a config file into dest_dir under the given filename.
fn copy_conf(src: &Path, dest_dir: &str, filename: &str) -> Result<()> {
    copy_file_if_changed(src, &Path::new(dest_dir).join(filename))
}

fn remove_files(paths: &[&str]) -> Result<()> {
    for path in paths {
        if Path::new(path).exists() {
            fs::remove_file(path).with_context(|| format!("Failed to remove {path}"))?;
            println!("Removed: {path}");
        }
    }
    Ok(())
}

fn require_root() -> Result<()> {
    let uid: u32 = String::from_utf8_lossy(&Command::new("id").arg("-u").output()?.stdout)
        .trim()
        .parse()?;
    if uid != 0 {
        bail!("This command must be run as root (sudo cargo xtask ...)");
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

fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let dst_path = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_all(&entry.path(), &dst_path)?;
        } else {
            fs::copy(entry.path(), dst_path)?;
        }
    }
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
