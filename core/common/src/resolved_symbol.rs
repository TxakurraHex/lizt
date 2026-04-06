use crate::process_runner::run;
use log::{debug, error, info};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeType {
    KProbe,
    UProbe,
}

impl std::fmt::Display for ProbeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeType::KProbe => write!(f, "kprobe"),
            ProbeType::UProbe => write!(f, "uprobe"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedSymbol {
    pub binary_path: PathBuf,
    pub probe_type: ProbeType,
}
pub struct SymbolIndex {
    pub entries: HashMap<String, Vec<ResolvedSymbol>>,
}

impl SymbolIndex {
    pub fn build(package_hints: &[(String, String)]) -> Self {
        let mut entries: HashMap<String, Vec<ResolvedSymbol>> = HashMap::new();

        if let Some(contents) = run("cat /proc/kallsyms") {
            for line in contents.lines() {
                if let Some(name) = line.split_whitespace().nth(2) {
                    entries
                        .entry(name.to_string())
                        .or_default()
                        .push(ResolvedSymbol {
                            binary_path: PathBuf::from("/proc/kallsyms"),
                            probe_type: ProbeType::KProbe,
                        });
                }
            }
        }

        info!("[build] Checking {} package hints", package_hints.len());
        for (package_name, inventory_source) in package_hints {
            let so_paths = match inventory_source.as_str() {
                source if source.contains("dpkg") => dpkg_library_files(package_name),
                source if source.contains("pip") => pip_library_files(package_name),
                source if source.contains("static") => static_library_files(package_name),
                _ => {
                    debug!(
                        "[build] invalid inventory_source pathname: {}",
                        inventory_source.as_str()
                    );
                    continue;
                }
            };

            for lib_path in so_paths {
                for sym_name in exported_symbols(&lib_path) {
                    entries.entry(sym_name).or_default().push(ResolvedSymbol {
                        binary_path: lib_path.clone(),
                        probe_type: ProbeType::UProbe,
                    });
                }
            }
        }

        Self { entries }
    }

    pub fn resolve(&self, name: &str) -> Option<&[ResolvedSymbol]> {
        self.entries.get(name).map(|v| v.as_slice())
    }

    pub fn is_available(&self) -> bool {
        !self.entries.is_empty()
    }
}

fn exported_symbols(lib_path: &Path) -> Vec<String> {
    let path_str = lib_path.display();
    let cmd = format!("nm --defined-only {path_str} 2>/dev/null");
    debug!("[exported_symbols] cmd = {cmd}");
    let Some(output) = run(&cmd) else {
        return vec![];
    };

    output
        .lines()
        .filter_map(|line| line.split_whitespace().nth(2))
        .map(String::from)
        .collect()
}

/// Returns installed package names whose dpkg name fuzzy-matches `hint`.
fn get_dpkg_candidates(hint: &str) -> Vec<String> {
    debug!("[get_dpkg_candidates]: hint = {}", hint);
    let Some(out) = run(format!("dpkg-query -W -f='${{Package}}\\n' \"*{hint}*\"").as_str()) else {
        return vec![];
    };
    out.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

fn static_library_files(package_name: &str) -> Vec<PathBuf> {
    let mut paths = vec![];
    match package_name {
        "bash" => paths.push(PathBuf::from("/opt/vulnerable/bin/bash")),
        "libexpat" => paths.push(PathBuf::from("/opt/vulnerable/lib/libexpat.so.1")),
        "openssl" => paths.push(PathBuf::from("/opt/vulnerable/lib/libcrypto.so.1.1")),
        "zlib" => paths.push(PathBuf::from("/opt/vulnerable/lib/libz.so.1")),
        _ => error!("Static package {} not supported", package_name),
    };
    paths
}

fn dpkg_library_files(package_name: &str) -> Vec<PathBuf> {
    let mut paths = vec![];
    for package in get_dpkg_candidates(package_name) {
        let cmd = format!("dpkg -L {package}");
        debug!("[dpkg_library_files]: cmd = {cmd}");
        let Some(files) = run(&cmd) else {
            continue;
        };

        for file in files.lines() {
            let file = file.trim();
            if file.contains(".so") {
                let path = PathBuf::from(file);
                if path.exists() {
                    paths.push(path);
                }
            }
        }
    }
    paths
}

fn pip_library_files(package_name: &str) -> Vec<PathBuf> {
    let cmd = format!("pip show {package_name}");
    debug!("[pip_library_files] cmd = {cmd}");
    let Some(out) = run(&cmd) else {
        return vec![];
    };
    let Some(location) = out
        .lines()
        .find(|line| line.starts_with("Location:"))
        .and_then(|line| line.strip_prefix("Location:"))
        .map(|location| location.trim().to_string())
    else {
        return vec![];
    };

    let Some(files) = run(&format!("find {location} -name '*.so'")) else {
        return vec![];
    };

    files
        .lines()
        .map(|line| PathBuf::from(line.trim()))
        .filter(|path| path.exists())
        .collect()
}
