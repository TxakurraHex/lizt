use crate::inventory::Source;
use crate::scraper_proc_runner::run;
use lizt_core::inventory_item::{
    CpeEntry, CpePart, InventoryItem, InventoryItemConfidence, InventorySource,
};

pub struct DpkgSource;

impl Source for DpkgSource {
    fn name(&self) -> &str {
        "dpkg"
    }

    fn collect(&self) -> Vec<InventoryItem> {
        let Some(out) = run("dpkg-query -W -f='${Package}\\t${Version}\\n'") else {
            return vec![];
        };

        out.lines()
            .filter_map(|line| {
                let (product, version) = line.split_once('\t')?;
                if product.starts_with("python3-") || product.starts_with("python-") {
                    None
                } else {
                    Some(InventoryItem {
                        cpe: CpeEntry {
                            part: CpePart::Application,
                            vendor: String::new(),
                            product: product.to_lowercase().replace("-", "_"),
                            version: Some(version.to_string()),
                        },
                        source: InventorySource::PackageManager(self.name().to_string()),
                        cpe_confidence: InventoryItemConfidence::Medium,
                    })
                }
            })
            .collect()
    }
}
