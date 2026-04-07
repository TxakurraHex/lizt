use crate::cpe::Cpe;
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct Cve {
    pub id: String,
    pub descriptions: Option<String>,
    pub published: Option<DateTime<Utc>>,
    pub refs: Option<Vec<CveRef>>,
    pub cvss_score: Option<Decimal>,
    pub cvss_vector: Option<String>,
    pub cvss_version: Option<String>,
    pub epss_score: Option<Decimal>,
    pub epss_percentile: Option<Decimal>,
    pub cpes: Option<Vec<CveCpe>>,
}

/// A CPE match condition from NVD (version ranges etc.)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CveCpe {
    pub cpe: Cpe,
    pub vulnerable: bool,
    pub version_start_including: Option<String>,
    pub version_start_excluding: Option<String>,
    pub version_end_including: Option<String>,
    pub version_end_excluding: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct CveRef {
    pub url: String,
    pub tags: Option<Vec<String>>,
}

impl CveCpe {
    pub fn matches_version(&self, installed_version: &str) -> bool {
        crate::version_cmp::version_in_range(
            installed_version,
            self.version_start_including.as_deref(),
            self.version_start_excluding.as_deref(),
            self.version_end_including.as_deref(),
            self.version_end_excluding.as_deref(),
        )
    }
}

impl Cve {
    pub fn affects_version(&self, vendor: &str, product: &str, installed_version: &str) -> bool {
        let cpe_matches = match &self.cpes {
            Some(cpes) if !cpes.is_empty() => cpes,
            _ => return true,
        };

        cpe_matches.iter().any(|m| {
            m.vulnerable
                && m.cpe.vendor == vendor
                && m.cpe.product == product
                && m.matches_version(installed_version)
        })
    }
}
