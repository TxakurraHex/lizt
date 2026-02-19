use serde::{Deserialize, Serialize};

/// Parsed CPE 2.3 entry from NVD dictionary or os-release
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpeEntry {
    pub part: CpePart,  // 'a' = application, 'o' = OS, 'h' = hardware
    pub vendor: String,
    pub product: String,
    pub version: Option<String>,
    pub raw: String,    // Original CPE string e.g. "cpe:2.3:o:cannonical:ubuntu_linux:24.04:..."
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CpePart {
    Application,
    OperatingSystem,
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

/// Represents a CPE determine from the running system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemCpe {
    pub cpe: CpeEntry,
    pub source: CpeSource,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum CpeSource {
    OsRelease,      // Read from /etc/os-release
    PackageManager, // rpm, dpkg, etc.
    ProcessMapping, // process -> package -> CPE
    FuzzyMatching,  // Fallback - NVD dictionary fuzzy search
}