//! Pre-built inventory fixtures for evaluation.
//!
//! Each fixture represents a specific vulnerable software version.
//! Pass one to the eval pipeline stage in place of real system sources.

use crate::inventory::Inventory;
use crate::sources::static_inv_source::StaticSource;

/// sudo 1.8.31: CVE-2021-3156 (Baron Samedit heap overflow)
pub fn sudo_cve_2021_3156() -> Inventory {
    Inventory::new(vec![Box::new(StaticSource::from_packages(
        "eval:sudo",
        &[("sudo", "sudo_project", "1.8.31")],
    ))])
}

/// bash 4.3: CVE-2014-6271 (Shellshock)
pub fn bash_cve_2014_6271() -> Inventory {
    Inventory::new(vec![Box::new(StaticSource::from_packages(
        "eval:bash",
        &[("bash", "gnu", "4.3")],
    ))])
}

/// libexpat 2.4.1: CVE-2022-25236 (namespace separator injection)
pub fn libexpat_cve_2022_25236() -> Inventory {
    Inventory::new(vec![Box::new(StaticSource::from_packages(
        "eval:libexpat",
        &[("expat", "libexpat_project", "2.4.1")],
    ))])
}

/// OpenSSL 1.1.1f: CVE-2022-0778 (BN_mod_sqrt infinite loop)
pub fn openssl_cve_2022_0778() -> Inventory {
    Inventory::new(vec![Box::new(StaticSource::from_packages(
        "eval:openssl",
        &[("openssl", "openssl", "1.1.1f")],
    ))])
}

/// All four eval fixtures combined.
pub fn all_eval_fixtures() -> Inventory {
    Inventory::new(vec![Box::new(StaticSource::from_packages(
        "eval:all",
        &[
            ("sudo", "sudo_project", "1.8.31"),
            ("bash", "gnu", "4.3"),
            ("expat", "libexpat_project", "2.4.1"),
            ("openssl", "openssl", "1.1.1f"),
        ],
    ))])
}
