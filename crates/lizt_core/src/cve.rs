use crate::inventory_item::CpeEntry;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct Cve {
    pub id: String,
    pub descriptions: Option<String>,
    pub published: Option<DateTime<Utc>>,
    pub references: Option<Vec<String>>,
    pub cvss: Option<CvssInfo>,
    pub cpes: Option<Vec<CpeMatch>>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct CvssInfo {
    pub score: f64,
    pub vector: String,
    pub version: String,
}

/// A CPE match condition from NVD (version ranges etc.)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CpeMatch {
    pub cpe_entry: CpeEntry,
    pub vulnerable: bool,
    pub version_start_including: Option<String>,
    pub version_start_excluding: Option<String>,
    pub version_end_including: Option<String>,
    pub version_end_excluding: Option<String>,
}
