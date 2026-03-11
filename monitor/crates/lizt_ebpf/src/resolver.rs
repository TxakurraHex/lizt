use std::path::PathBuf;
use std::str::FromStr;

use lizt_core::cpe::InventorySource;
use lizt_core::process_runner::run;
use log::{info, warn};

/// Finds the shared library path that exports `symbol_name`.
///
/// Search order:
/// 1. CPE-guided: dispatch to a package-manager-specific resolver based on
///    `package_source` (e.g. `"package_manager:dpkg"` or `"package_manager:pip"`),
///    using `package_hint` (the CPE product name) to narrow the search.
/// 2. Fallback: scan all entries in the `ldconfig -p` cache with `nm -D`.
///
/// Returns `None` if no library exporting the symbol can be found.
pub fn resolve_library(
    symbol_name: &str,
    package_hint: Option<&str>,
    package_source: Option<&str>,
) -> Option<PathBuf> {
    if let Some(source_str) = package_source {
        if let Ok(source) = InventorySource::from_str(source_str) {
            let path = match source {
                InventorySource::PackageManager(ref pm) if pm == "dpkg" => {
                    get_dpkg_library(symbol_name, package_hint)
                }
                InventorySource::PackageManager(ref pm) if pm == "pip" => {
                    get_pip_library(symbol_name, package_hint)
                }
                _ => None,
            };
            if path.is_some() {
                return path;
            }
        }
    }

    // Fallback: brute-force ldconfig cache
    // Format: "    libfoo.so.1 (libc6,x86-64) => /usr/lib/.../libfoo.so.1"
    if let Some(out) = run("ldconfig -p") {
        for line in out.lines() {
            let Some(path_str) = line.split("=>").nth(1) else {
                continue;
            };
            let path_str = path_str.trim();
            let path = PathBuf::from(path_str);
            if path.exists() && symbol_exported(path_str, symbol_name) {
                return Some(path);
            }
        }
    }

    warn!("could not resolve library for symbol '{symbol_name}'");
    None
}

/// Finds a `.so` file owned by a dpkg package that fuzzy-matches `package_hint`.
fn get_dpkg_library(symbol_name: &str, package_hint: Option<&str>) -> Option<PathBuf> {
    let hint = package_hint?;
    for package in get_dpkg_candidates(hint) {
        info!("Running dpkg -L {}", package);
        let Some(files) = run(format!("dpkg -L {package}").as_str()) else {
            continue;
        };
        for file in files.lines() {
            let file = file.trim();
            if !file.contains(".so") {
                continue;
            }
            let path = PathBuf::from(file);
            if path.exists() && symbol_exported(file, symbol_name) {
                return Some(path);
            }
        }
    }
    None
}

/// Finds a `.so` extension module under the pip package's install location.
fn get_pip_library(symbol_name: &str, package_hint: Option<&str>) -> Option<PathBuf> {
    let hint = package_hint?;
    let out = run(&format!("pip show {hint}"))?;
    let location = out
        .lines()
        .find(|l| l.starts_with("Location:"))?
        .strip_prefix("Location:")?
        .trim();
    let files = run(&format!("find {location} -name '*.so'"))?;
    for file in files.lines() {
        let file = file.trim();
        let path = PathBuf::from(file);
        if path.exists() && symbol_exported(file, symbol_name) {
            return Some(path);
        }
    }
    None
}

/// Returns installed package names whose dpkg name fuzzy-matches `hint`.
fn get_dpkg_candidates(hint: &str) -> Vec<String> {
    let Some(out) = run(format!("dpkg-query -W -f='${{Package}}\\n' \"*{hint}*\"").as_str()) else {
        return vec![];
    };
    out.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Returns true if `library_path` exports `symbol_name` in its dynamic symbol table.
fn symbol_exported(library_path: &str, symbol_name: &str) -> bool {
    let Some(out) = run(format!("nm -D --defined-only {library_path} 2>/dev/null").as_str()) else {
        return false;
    };
    out.lines().any(|line| {
        line.split_whitespace()
            .last()
            .is_some_and(|sym| sym == symbol_name)
    })
}
