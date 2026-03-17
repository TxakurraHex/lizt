use crate::inventory::Source;
use common::cpe::{Cpe, CpeEntry, CpePart, InventoryItemConfidence, InventorySource};
use common::process_runner::run;

pub struct DpkgSource;

impl Source for DpkgSource {
    fn name(&self) -> &str {
        "dpkg"
    }

    fn collect(&self) -> Vec<CpeEntry> {
        let Some(out) = run("dpkg-query -W -f='${Package}\\t${Version}\\n'") else {
            return vec![];
        };

        out.lines()
            .filter_map(|line| {
                let (product, version) = line.split_once('\t')?;
                if product.starts_with("python3-") || product.starts_with("python-") {
                    None
                } else {
                    Some(CpeEntry {
                        cpe: Cpe {
                            name: product.to_string(),
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
