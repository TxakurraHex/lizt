//! Install paths and layout constraints
//!
//! Both `install` and `verify` read these. Keeping them in one place means a
//! path change in one subcommand cannot silently de-sync from the other.

use std::path::{Path, PathBuf};

pub const BIN_DIR: &str = "/usr/bin";
pub const CONF_DIR: &str = "/etc/lizt";
pub const LOG_DIR: &str = "/var/log/lizt";
pub const SYSTEMD_DIR: &str = "/etc/systemd/system";
pub const NGINX_SITES_AVAIL: &str = "/etc/nginx/sites-available";
pub const NGINX_SITES_ENABLED: &str = "/etc/nginx/sites-enabled";
pub const NGINX_SSL_DIR: &str = "/etc/nginx/ssl";
pub const NGINX_HTPASSWD: &str = "/etc/nginx/.lizt_htpasswd";

pub const LIZT_USER: &str = "lizt";
pub const LIZT_SERVICE: &str = "lizt";

/// Capabilities the systemd unit grants via `AmbientCapabilities`.
/// Keep this in sync with `scanner/web/conf/lizt.service`.
pub const EXPECTED_CAPS: &[&str] = &[
    "cap_bpf",
    "cap_perfmon",
    "cap_sys_admin",
    "cap_sys_resource",
];

pub fn lizt_bin() -> PathBuf {
    Path::new(BIN_DIR).join("lizt")
}
pub fn lizt_cli_bin() -> PathBuf {
    Path::new(BIN_DIR).join("lizt-cli")
}
pub fn env_file() -> PathBuf {
    Path::new(CONF_DIR).join("env")
}
pub fn log4rs_web() -> PathBuf {
    Path::new(CONF_DIR).join("log4rs.yaml")
}
pub fn log4rs_cli() -> PathBuf {
    Path::new(CONF_DIR).join("cli_log4rs.yaml")
}
pub fn migrations_dir() -> PathBuf {
    Path::new(CONF_DIR).join("migrations")
}
pub fn systemd_unit() -> PathBuf {
    Path::new(SYSTEMD_DIR).join("lizt.service")
}
pub fn nginx_site_avail() -> PathBuf {
    Path::new(NGINX_SITES_AVAIL).join("lizt")
}
pub fn nginx_site_enabled() -> PathBuf {
    Path::new(NGINX_SITES_ENABLED).join("lizt")
}
pub fn tls_cert() -> PathBuf {
    Path::new(NGINX_SSL_DIR).join("lizt.crt")
}
pub fn tls_key() -> PathBuf {
    Path::new(NGINX_SSL_DIR).join("lizt.key")
}
