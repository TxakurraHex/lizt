//! Pre-built inventory fixtures for evaluation.
//!
//! Each fixture represents a specific vulnerable software version.
//! Pass one to the eval pipeline stage in place of real system sources.

use crate::inventory::Inventory;
use crate::sources::static_inv_source::StaticSource;

/// libexpat 2.4.1: CVE-2022-25236 (namespace separator injection)
pub fn libexpat_cve_2022_25236() -> Inventory {
    Inventory::new(vec![Box::new(StaticSource::from_packages(
        "eval:libexpat",
        &[("expat", "libexpat_project", "2.2.9")],
    ))])
}

/// OpenSSL 1.1.1f: CVE-2022-0778 (BN_mod_sqrt infinite loop)
pub fn openssl_cve_2022_0778() -> Inventory {
    Inventory::new(vec![Box::new(StaticSource::from_packages(
        "eval:openssl",
        &[("openssl", "openssl", "1.1.1f")],
    ))])
}

/// zlib 1.2.11: CVE-2022-37434 (inflate heap overflow via large gzip header)
pub fn zlib_cve_2022_37434() -> Inventory {
    Inventory::new(vec![Box::new(StaticSource::from_packages(
        "eval:zlib",
        &[("zlib", "zlib", "1.2.11")],
    ))])
}

/// All four eval fixtures combined.
pub fn all_eval_fixtures() -> Inventory {
    Inventory::new(vec![Box::new(StaticSource::from_packages(
        "eval:all",
        &[
            ("expat", "libexpat_project", "2.4.1"),
            ("openssl", "openssl", "1.1.1f"),
            ("zlib", "zlib", "1.2.11"),
        ],
    ))])
}
