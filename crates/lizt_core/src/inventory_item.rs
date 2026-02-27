use serde::{Deserialize, Serialize};
use std::fmt;
use strum::{Display, EnumString};

/// Represents a CPE determine from the running system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryItem {
    pub cpe: CpeEntry,
    pub source: InventorySource,
    pub cpe_confidence: InventoryItemConfidence,
}

/// Parsed CPE 2.3 entry from NVD dictionary or os-release
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CpeEntry {
    pub part: CpePart, // 'a' = application, 'o' = OS, 'h' = hardware
    pub vendor: String,
    pub product: String,
    pub version: Option<String>,
}

impl CpeEntry {
    pub fn to_cpe_string(&self) -> String {
        if let Some(version) = &self.version {
            format!(
                "cpe:2.3:{}:{}:{}:{}",
                self.part, self.vendor, self.product, version
            )
        } else {
            format!("cpe:2.3:{}:{}:{}", self.part, self.vendor, self.product)
        }
    }
    pub fn from_cpe_string(criteria: &str) -> Self {
        let parts: Vec<&str> = criteria.split(':').collect();

        CpeEntry {
            part: parts
                .get(2)
                .map(|p| match *p {
                    "a" => CpePart::Application,
                    "o" => CpePart::OperatingSystem,
                    "h" => CpePart::Hardware,
                    _ => CpePart::Unknown,
                })
                .unwrap_or(CpePart::Unknown),
            vendor: parts.get(3).unwrap_or(&"*").to_string(),
            product: parts.get(4).unwrap_or(&"*").to_string(),
            version: parts.get(5).filter(|v| **v != "*").map(|v| v.to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Display, EnumString, PartialEq, Eq)]
pub enum CpePart {
    #[strum(serialize = "a")]
    Application,
    #[strum(serialize = "o")]
    OperatingSystem,
    #[strum(serialize = "h")]
    Hardware,
    Unknown,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub enum InventorySource {
    OsInfo(String),         // Read from /etc/os-release, `uname -r`, etc.
    PackageManager(String), // rpm, dpkg, etc.
    ProcessMapping(String), // process -> package -> CPE
    FuzzyMatching(String),  // Fallback - NVD dictionary fuzzy search
    Unknown(String),
}

impl fmt::Display for InventorySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InventorySource::OsInfo(os_info) => write!(f, "os_info:{}", os_info),
            InventorySource::PackageManager(pm) => write!(f, "package_manager:{}", pm),
            InventorySource::ProcessMapping(pm) => write!(f, "process_mapping:{}", pm),
            InventorySource::FuzzyMatching(fpm) => write!(f, "fuzzy_matching:{}", fpm),
            InventorySource::Unknown(unknown) => write!(f, "unknown:{}", unknown),
        }
    }
}

impl std::str::FromStr for InventorySource {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once(':') {
            Some(("os_info", os_info)) => Ok(InventorySource::OsInfo(os_info.to_string())),
            Some(("package_manager", pm)) => Ok(InventorySource::PackageManager(pm.to_string())),
            Some(("process_mapping", pm)) => Ok(InventorySource::ProcessMapping(pm.to_string())),
            Some(("fuzzy_matching", pm)) => Ok(InventorySource::FuzzyMatching(pm.to_string())),
            Some(("unknown", unk)) => Ok(InventorySource::Unknown(unk.to_string())),
            _ => Err("unknown inventory source".to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, EnumString, Display)]
#[strum(serialize_all = "lowercase")]
pub enum InventoryItemConfidence {
    High,
    Medium,
    Low,
}
