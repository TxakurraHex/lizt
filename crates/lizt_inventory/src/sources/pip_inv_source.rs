use crate::inventory::Source;
use crate::scraper_proc_runner::run;
use lizt_core::inventory_item::{
    CpeEntry, CpePart, InventoryItem, InventoryItemConfidence, InventorySource,
};
use serde::Deserialize;
use tracing::error;

#[derive(Deserialize)]
struct PipPackage {
    name: String,
    version: String,
}

pub struct PipSource;

impl Source for PipSource {
    fn name(&self) -> &str {
        "pip"
    }

    fn collect(&self) -> Vec<InventoryItem> {
        let Some(out) = run("python3 -m pip list --format=json 2>/dev/null") else {
            return vec![];
        };

        match serde_json::from_str::<Vec<PipPackage>>(&out) {
            Ok(pkgs) => pkgs
                .into_iter()
                .map(|pkg| InventoryItem {
                    cpe: CpeEntry {
                        part: CpePart::Application,
                        vendor: String::new(),
                        product: pkg.name.to_lowercase().replace("-", "_"),
                        version: Some(pkg.version),
                    },
                    source: InventorySource::PackageManager(self.name().to_string()),
                    cpe_confidence: InventoryItemConfidence::Low,
                })
                .collect(),
            Err(e) => {
                error!("Failed to decode `pip list` results: {}", e);
                vec![]
            }
        }
    }
}
