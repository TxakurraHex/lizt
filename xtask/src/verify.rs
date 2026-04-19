//! `cargo xtask verify` — sanity-check an installed Lizt deployment.
//!
//! Runs a suite of independent checks, prints a human checklist, and writes a
//! JSON summary to a caller-specified path (or `/tmp/lizt-verify.json` by
//! default). Exits non-zero if any check fails. Must be run as root.

use std::fs;
use std::io::Read;
use std::net::TcpStream;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::paths::{self, EXPECTED_CAPS, LIZT_SERVICE, LIZT_USER};
use anyhow::{Context, Result, bail};
use serde::Serialize;

/// Outcome of a single check.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "lowercase")]
enum Status {
    Pass,
    Fail,
    Warn,
}

#[derive(Serialize, Clone, Debug)]
struct CheckResult {
    name: String,
    status: Status,
    detail: String,
}

impl CheckResult {
    fn pass(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: Status::Pass,
            detail: detail.into(),
        }
    }
    fn fail(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: Status::Fail,
            detail: detail.into(),
        }
    }
    fn warn(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: Status::Warn,
            detail: detail.into(),
        }
    }
}

#[derive(Serialize)]
struct Report {
    passed: usize,
    failed: usize,
    warned: usize,
    checks: Vec<CheckResult>,
}

/// Entry point invoked from `main.rs`.
pub fn verify(json_out: &Path) -> Result<()> {
    require_root()?;

    let mut checks: Vec<CheckResult> = Vec::new();

    checks.push(check_file_mode(&paths::lizt_bin(), 0o755));
    checks.push(check_file_mode(&paths::lizt_cli_bin(), 0o755));
    checks.push(check_file_mode(&paths::env_file(), 0o600));
    checks.push(check_file_mode(&paths::log4rs_web(), 0o644));
    checks.push(check_file_mode(&paths::log4rs_cli(), 0o644));
    checks.push(check_file_mode(&paths::systemd_unit(), 0o644));
    checks.push(check_file_mode(&paths::tls_cert(), 0o644));
    checks.push(check_file_exists(&paths::tls_key()));
    checks.push(check_file_exists(Path::new(paths::NGINX_HTPASSWD)));
    checks.push(check_dir_populated(&paths::migrations_dir()));
    checks.push(check_nginx_site_enabled());
    checks.push(check_lizt_user_exists());
    checks.push(check_log_dir_ownership());
    checks.push(check_env_file_contents());
    checks.push(check_binary_capabilities());
    checks.push(check_tls_cert_not_expired());
    checks.push(check_systemd_enabled());
    checks.push(check_systemd_active());
    checks.push(check_nginx_config_valid());
    checks.push(check_port_443_listening());
    checks.push(check_dashboard_responds());

    // Tally.
    let passed = checks
        .iter()
        .filter(|c| matches!(c.status, Status::Pass))
        .count();
    let failed = checks
        .iter()
        .filter(|c| matches!(c.status, Status::Fail))
        .count();
    let warned = checks
        .iter()
        .filter(|c| matches!(c.status, Status::Warn))
        .count();

    // Human output.
    println!("\nLizt install verification");
    println!("─────────────────────────");
    for c in &checks {
        let mark = match c.status {
            Status::Pass => "✓",
            Status::Fail => "✗",
            Status::Warn => "!",
        };
        println!("  {mark} {:<32}  {}", c.name, c.detail);
    }
    println!("─────────────────────────");
    println!("{passed} passed, {failed} failed, {warned} warned");

    // JSON output.
    let report = Report {
        passed,
        failed,
        warned,
        checks,
    };
    let json = serde_json::to_string_pretty(&report)?;
    fs::write(json_out, json)
        .with_context(|| format!("Failed to write JSON report to {}", json_out.display()))?;
    println!("JSON report: {}", json_out.display());

    if failed > 0 {
        bail!("{failed} check(s) failed");
    }
    Ok(())
}

// ── individual checks ────────────────────────────────────────────────────────

fn check_file_exists(path: &Path) -> CheckResult {
    let name = format!("exists: {}", path.display());
    if path.exists() {
        CheckResult::pass(name, "present")
    } else {
        CheckResult::fail(name, "missing")
    }
}

fn check_file_mode(path: &Path, expected: u32) -> CheckResult {
    let name = format!("mode {:o}: {}", expected, path.display());
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => return CheckResult::fail(name, format!("stat failed: {e}")),
    };
    let actual = meta.permissions().mode() & 0o777;
    if actual == expected {
        CheckResult::pass(name, format!("{actual:o}"))
    } else {
        CheckResult::fail(name, format!("got {actual:o}, want {expected:o}"))
    }
}

fn check_dir_populated(path: &Path) -> CheckResult {
    let name = format!("populated: {}", path.display());
    let rd = match fs::read_dir(path) {
        Ok(r) => r,
        Err(e) => return CheckResult::fail(name, format!("read_dir failed: {e}")),
    };
    let count = rd.count();
    if count > 0 {
        CheckResult::pass(name, format!("{count} entries"))
    } else {
        CheckResult::fail(name, "empty directory")
    }
}

fn check_nginx_site_enabled() -> CheckResult {
    let name = "nginx site enabled".to_string();
    let link = paths::nginx_site_enabled();
    match fs::symlink_metadata(&link) {
        Err(e) => CheckResult::fail(name, format!("stat failed: {e}")),
        Ok(m) if !m.file_type().is_symlink() => {
            CheckResult::fail(name, format!("{} is not a symlink", link.display()))
        }
        Ok(_) => match fs::read_link(&link) {
            Ok(target) if target == paths::nginx_site_avail() => {
                CheckResult::pass(name, format!("-> {}", target.display()))
            }
            Ok(target) => CheckResult::fail(
                name,
                format!(
                    "-> {} (expected {})",
                    target.display(),
                    paths::nginx_site_avail().display()
                ),
            ),
            Err(e) => CheckResult::fail(name, format!("readlink failed: {e}")),
        },
    }
}

fn check_lizt_user_exists() -> CheckResult {
    let name = format!("user exists: {LIZT_USER}");
    match Command::new("id").arg(LIZT_USER).output() {
        Ok(out) if out.status.success() => CheckResult::pass(name, "present"),
        Ok(_) => CheckResult::fail(name, "user not found"),
        Err(e) => CheckResult::fail(name, format!("id failed: {e}")),
    }
}

fn check_log_dir_ownership() -> CheckResult {
    let name = format!("ownership: {}", paths::LOG_DIR);
    let meta = match fs::metadata(paths::LOG_DIR) {
        Ok(m) => m,
        Err(e) => return CheckResult::fail(name, format!("stat failed: {e}")),
    };
    // Resolve `lizt` uid via `id -u lizt`.
    let want_uid = match Command::new("id").args(["-u", LIZT_USER]).output() {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse::<u32>()
            .ok(),
        _ => None,
    };
    match want_uid {
        Some(uid) if meta.uid() == uid => CheckResult::pass(name, format!("owner uid {uid}")),
        Some(uid) => CheckResult::fail(name, format!("owner uid {} want {uid}", meta.uid())),
        None => CheckResult::warn(name, "could not resolve lizt uid"),
    }
}

fn check_env_file_contents() -> CheckResult {
    let name = "env has DATABASE_URL (non-default)".to_string();
    let contents = match fs::read_to_string(paths::env_file()) {
        Ok(s) => s,
        Err(e) => return CheckResult::fail(name, format!("read failed: {e}")),
    };
    let Some(line) = contents.lines().find(|l| l.starts_with("DATABASE_URL=")) else {
        return CheckResult::fail(name, "DATABASE_URL= line missing");
    };
    let value = line.trim_start_matches("DATABASE_URL=");
    if value.contains("user:password@localhost") {
        CheckResult::fail(name, "DATABASE_URL is still the template default")
    } else if value.is_empty() {
        CheckResult::fail(name, "DATABASE_URL is empty")
    } else {
        CheckResult::pass(name, "set to a non-default value")
    }
}

fn check_binary_capabilities() -> CheckResult {
    // The systemd unit grants capabilities via AmbientCapabilities, not via
    // filesystem file caps. `getcap` on /usr/bin/lizt will typically be empty
    // on a normal systemd install — so this is a warning, not a failure, and
    // we additionally parse the unit file to make sure the unit itself still
    // declares the caps we expect.
    let name = "systemd unit caps".to_string();
    let unit = match fs::read_to_string(paths::systemd_unit()) {
        Ok(s) => s,
        Err(e) => return CheckResult::fail(name, format!("read unit failed: {e}")),
    };
    let ambient_line = unit
        .lines()
        .find(|l| l.trim_start().starts_with("AmbientCapabilities="));
    let Some(line) = ambient_line else {
        return CheckResult::fail(name, "AmbientCapabilities= not found in unit");
    };
    let declared: Vec<&str> = line
        .trim_start()
        .trim_start_matches("AmbientCapabilities=")
        .split_whitespace()
        .collect();
    let declared_lower: Vec<String> = declared.iter().map(|s| s.to_ascii_lowercase()).collect();
    let missing: Vec<&&str> = EXPECTED_CAPS
        .iter()
        .filter(|c| !declared_lower.iter().any(|d| d == **c))
        .collect();
    if missing.is_empty() {
        CheckResult::pass(name, format!("declares {}", declared.join(" ")))
    } else {
        CheckResult::fail(
            name,
            format!(
                "missing caps: {}",
                missing.iter().map(|c| **c).collect::<Vec<_>>().join(" ")
            ),
        )
    }
}

fn check_tls_cert_not_expired() -> CheckResult {
    let name = "TLS cert not expired".to_string();
    let out = match Command::new("openssl")
        .args(["x509", "-in"])
        .arg(paths::tls_cert())
        .args(["-noout", "-checkend", "0"])
        .output()
    {
        Ok(o) => o,
        Err(e) => return CheckResult::fail(name, format!("openssl failed: {e}")),
    };
    if out.status.success() {
        // Additionally warn if the cert expires within 30 days.
        let soon = Command::new("openssl")
            .args(["x509", "-in"])
            .arg(paths::tls_cert())
            .args(["-noout", "-checkend", &(30 * 24 * 3600).to_string()])
            .status();
        match soon {
            Ok(s) if s.success() => CheckResult::pass(name, "valid >30 days"),
            Ok(_) => CheckResult::warn(name, "expires within 30 days"),
            Err(_) => CheckResult::pass(name, "valid"),
        }
    } else {
        CheckResult::fail(name, "cert is expired")
    }
}

fn check_systemd_enabled() -> CheckResult {
    let name = format!("systemd: {LIZT_SERVICE} enabled");
    match Command::new("systemctl")
        .args(["is-enabled", LIZT_SERVICE])
        .output()
    {
        Ok(out) if out.status.success() => CheckResult::pass(
            name,
            String::from_utf8_lossy(&out.stdout).trim().to_string(),
        ),
        Ok(out) => CheckResult::fail(
            name,
            String::from_utf8_lossy(&out.stdout).trim().to_string(),
        ),
        Err(e) => CheckResult::fail(name, format!("systemctl failed: {e}")),
    }
}

fn check_systemd_active() -> CheckResult {
    let name = format!("systemd: {LIZT_SERVICE} active");
    match Command::new("systemctl")
        .args(["is-active", LIZT_SERVICE])
        .output()
    {
        Ok(out) if out.status.success() => CheckResult::pass(name, "active"),
        Ok(out) => CheckResult::fail(
            name,
            String::from_utf8_lossy(&out.stdout).trim().to_string(),
        ),
        Err(e) => CheckResult::fail(name, format!("systemctl failed: {e}")),
    }
}

fn check_nginx_config_valid() -> CheckResult {
    let name = "nginx -t".to_string();
    match Command::new("nginx").arg("-t").output() {
        Ok(out) if out.status.success() => CheckResult::pass(name, "valid"),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            CheckResult::fail(name, stderr.lines().last().unwrap_or("invalid").to_string())
        }
        Err(e) => CheckResult::fail(name, format!("nginx failed: {e}")),
    }
}

fn check_port_443_listening() -> CheckResult {
    let name = "port 443 listening".to_string();
    match TcpStream::connect_timeout(&"127.0.0.1:443".parse().unwrap(), Duration::from_secs(2)) {
        Ok(_) => CheckResult::pass(name, "accepting connections"),
        Err(e) => CheckResult::fail(name, format!("connect failed: {e}")),
    }
}

fn check_dashboard_responds() -> CheckResult {
    // Full HTTPS request, expect 401 Unauthorized (basic auth required).
    // Self-signed cert is expected, so we disable cert verification.
    let name = "dashboard returns 401".to_string();

    let tls = match native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
    {
        Ok(t) => t,
        Err(e) => return CheckResult::fail(name, format!("TLS setup failed: {e}")),
    };

    let agent = ureq::AgentBuilder::new()
        .tls_connector(std::sync::Arc::new(tls))
        .timeout(Duration::from_secs(3))
        .build();

    match agent.get("https://127.0.0.1/").call() {
        Err(ureq::Error::Status(401, _)) => CheckResult::pass(name, "401 Unauthorized"),
        Err(ureq::Error::Status(code, _)) => {
            CheckResult::fail(name, format!("got HTTP {code}, want 401"))
        }
        Ok(resp) => CheckResult::fail(
            name,
            format!("got HTTP {} (auth not enforced?)", resp.status()),
        ),
        Err(e) => CheckResult::fail(name, format!("request failed: {e}")),
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn require_root() -> Result<()> {
    let mut out = String::new();
    Command::new("id")
        .arg("-u")
        .output()?
        .stdout
        .as_slice()
        .read_to_string(&mut out)?;
    let uid: u32 = out.trim().parse()?;
    if uid != 0 {
        bail!("`verify` must be run as root (sudo cargo xtask verify)");
    }
    Ok(())
}
