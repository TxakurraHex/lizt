use lizt_core::inventory_item::{InventoryItem, InventorySource};
use radix_trie::Trie;
use regex::Regex;
use std::collections::HashSet;
use std::sync::OnceLock;

/// Trie to convert common libraries and binaries to known CPE values
fn vendor_trie() -> &'static Trie<String, (&'static str, &'static str)> {
    static TRIE: OnceLock<Trie<String, (&'static str, &'static str)>> = OnceLock::new();
    TRIE.get_or_init(|| {
        let mut trie = Trie::new();
        let mappings: &[(&str, (&str, &str))] = &[
            ("openssl", ("openssl", "openssl")),
            ("openssh", ("openbsd", "openssh")),
            ("openssh_server", ("openbsd", "openssh")),
            ("openssh_client", ("openbsd", "openssh")),
            ("curl", ("haxx", "curl")),
            ("libcurl", ("haxx", "curl")),
            ("nginx", ("nginx", "nginx")),
            ("apache2", ("apache", "http_server")),
            ("httpd", ("apache", "http_server")),
            ("postgresql", ("postgresql", "postgresql")),
            ("mysql", ("mysql", "mysql")),
            ("sqlite3", ("sqlite", "sqlite")),
            ("libsqlite3", ("sqlite", "sqlite")),
            ("python3", ("python", "python")),
            ("python", ("python", "python")),
            ("pip", ("pypa", "pip")),
            ("git", ("git-scm", "git")),
            ("bash", ("gnu", "bash")),
            ("vim", ("vim", "vim")),
            ("zsh", ("zsh", "zsh")),
            ("sudo", ("sudo_project", "sudo")),
            ("glibc", ("gnu", "glibc")),
            ("libc6", ("gnu", "glibc")),
            ("linux_image", ("linux", "linux_kernel")),
            ("rsync", ("samba", "rsync")),
            ("tar", ("gnu", "tar")),
            ("wget", ("gnu", "wget")),
            ("zip", ("info-zip", "zip")),
            ("unzip", ("info-zip", "unzip")),
            ("expat", ("libexpat_project", "libexpat")),
            ("libexpat1", ("libexpat_project", "libexpat")),
            ("zlib", ("zlib", "zlib")),
            ("zlib1g", ("zlib", "zlib")),
            ("libssl", ("openssl", "openssl")),
            ("libpng", ("libpng", "libpng")),
            ("libtiff", ("libtiff", "libtiff")),
            ("libjpeg", ("ijg", "libjpeg")),
            ("libxml2", ("xmlsoft", "libxml2")),
            ("libxslt", ("xmlsoft", "libxslt")),
            ("dbus", ("freedesktop", "dbus")),
            ("systemd", ("systemd_project", "systemd")),
            ("perl", ("perl", "perl")),
            ("ruby", ("ruby-lang", "ruby")),
            ("nodejs", ("nodejs", "node.js")),
            ("node", ("nodejs", "node.js")),
            ("npm", ("npmjs", "npm")),
            ("java", ("oracle", "jdk")),
            ("openjdk", ("openjdk", "openjdk")),
            ("php", ("php", "php")),
            ("ffmpeg", ("ffmpeg", "ffmpeg")),
            ("imagemagick", ("imagemagick", "imagemagick")),
            ("g++", ("gnu", "g\\+\\+")),
        ];
        for (key, value) in mappings {
            trie.insert(key.to_string(), *value);
        }
        trie
    })
}

pub trait Source {
    fn name(&self) -> &str;
    fn collect(&self) -> Vec<InventoryItem>;
}

pub struct Inventory {
    pub sources: Vec<Box<dyn Source>>,
    pub items: Vec<InventoryItem>,
}

impl Inventory {
    pub fn new(sources: Vec<Box<dyn Source>>) -> Self {
        Self {
            sources,
            items: Vec::new(),
        }
    }

    pub fn collect(&mut self) {
        let mut seen: HashSet<String> = HashSet::new();
        for source in &self.sources {
            for item in source.collect() {
                let normalized = normalize_system_cpe(&item);
                if seen.insert(normalized.cpe.to_cpe_string()) {
                    self.items.push(normalized.clone());
                }
                // TODO: Add alternative versions with 'lib' prefix and any version suffixes removed
            }
        }
    }

    pub fn filter_by_source(&self, source: &InventorySource) -> Vec<&InventoryItem> {
        self.items.iter().filter(|i| &i.source == source).collect()
    }
}
/// Function to ensure Regex compilation only happens once
fn version_cleanup_regexes() -> &'static [Regex] {
    static REGEXES: OnceLock<Vec<Regex>> = OnceLock::new();
    REGEXES.get_or_init(|| {
        vec![
            Regex::new(r"^\d+:").unwrap(),
            Regex::new(r"^.*?really").unwrap(),
            Regex::new(r"\+(dfsg|ds|repack|git|nmu|tests)[^-]*").unwrap(),
            Regex::new(r"[+~].*$").unwrap(),
            Regex::new(r"ubuntu[\d.]+").unwrap(),
            Regex::new(r"build\d+").unwrap(),
            Regex::new(r"-\d+(\.\d+)*$").unwrap(),
        ]
    })
}

fn libname_cleanup_regexes() -> &'static [Regex] {
    static REGEXES: OnceLock<Vec<Regex>> = OnceLock::new();
    REGEXES.get_or_init(|| vec![Regex::new(r"\d.*$").unwrap(), Regex::new(r"^lib").unwrap()])
}

fn normalize_version(version: &str) -> String {
    let mut v = version.to_string();
    for re in version_cleanup_regexes() {
        v = re.replace(&v, "").to_string();
    }
    v.trim_end_matches(['-', '.']).to_string()
}

fn normalize_system_cpe(cpe_item: &InventoryItem) -> InventoryItem {
    let product_lower = cpe_item.cpe.product.to_lowercase();
    let mut new_item = cpe_item.clone();

    if let Some((vendor, product)) = vendor_trie().get_ancestor_value(&product_lower) {
        new_item.cpe.vendor = vendor.to_string();
        new_item.cpe.product = product.to_string();
    }

    if let Some(version) = cpe_item.cpe.version.as_deref() {
        new_item.cpe.version = Some(normalize_version(version));
    }

    new_item
}
