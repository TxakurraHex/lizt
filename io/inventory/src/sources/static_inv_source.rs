use crate::inventory::Source;
use common::cpe::{Cpe, CpeEntry, CpePart, InventoryItemConfidence, InventorySource};

pub struct StaticSource {
    name: String,
    entries: Vec<CpeEntry>,
}

impl StaticSource {
    pub fn new(name: impl Into<String>, entries: Vec<CpeEntry>) -> Self {
        Self {
            name: name.into(),
            entries,
        }
    }

    pub fn from_packages(name: impl Into<String>, pkgs: &[(&str, &str, &str)]) -> Self {
        let entries = pkgs
            .iter()
            .map(|(product, vendor, version)| CpeEntry {
                cpe: Cpe {
                    name: product.to_string(),
                    part: CpePart::Application,
                    vendor: vendor.to_string(),
                    product: product.to_lowercase().replace("-", "_"),
                    version: Some(version.to_string()),
                },
                source: InventorySource::PackageManager("static".to_string()),
                cpe_confidence: InventoryItemConfidence::High,
            })
            .collect();
        Self::new(name, entries)
    }
}

impl Source for StaticSource {
    fn name(&self) -> &str {
        &self.name
    }

    fn collect(&self) -> Vec<CpeEntry> {
        self.entries.clone()
    }
}
