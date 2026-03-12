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
