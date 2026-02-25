use std::fmt;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

/// Represents a CPE determine from the running system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemCpe {
    pub cpe: CpeEntry,
    pub source: CpeSource,
}

/// Parsed CPE 2.3 entry from NVD dictionary or os-release
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpeEntry {
    pub part: CpePart, // 'a' = application, 'o' = OS, 'h' = hardware
    pub vendor: String,
    pub product: String,
    pub version: Option<String>,
}

impl CpeEntry {
    pub fn match_string(&self) -> String {
        if let Some(version) = &self.version {
            format!("cpe:2.3:{}:{}:{}:{}", self.part, self.vendor, self.product, version)
        } else {
            format!("cpe:2.3:{}:{}:{}", self.part, self.vendor, self.product)
        }
    }
}

impl fmt::Display for CpeEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cpe:2.3:{}:{}:{}", self.part, self.vendor, self.product)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Display, EnumString)]
pub enum CpePart {
    #[strum(serialize = "a")]
    Application,
    #[strum(serialize = "o")]
    OperatingSystem,
    #[strum(serialize = "h")]
    Hardware,
    Unknown,
}

/// A CPE match condition from NVD (version ranges etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpeMatch {
    pub cpe_entry: CpeEntry,
    pub vulnerable: bool,
    pub version_start_including: Option<String>,
    pub version_start_excluding: Option<String>,
    pub version_end_including: Option<String>,
    pub version_end_excluding: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub enum CpeSource {
    OsInfo(String),         // Read from /etc/os-release, `uname -r`, etc.
    PackageManager(String), // rpm, dpkg, etc.
    ProcessMapping(String), // process -> package -> CPE
    FuzzyMatching(String),  // Fallback - NVD dictionary fuzzy search
}