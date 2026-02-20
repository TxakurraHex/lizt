use crate::cpe::{CpeEntry, CpePart, CpeSource, SystemCpe};
use crate::inventory::Source;
use crate::runner::run;
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

    fn collect(&self) -> Vec<SystemCpe> {
        let Some(out) = run("python3 -m pip list --format=json 2>/dev/null") else {
            return vec![];
        };

        match serde_json::from_str::<Vec<PipPackage>>(&out) {
            Ok(pkgs) => pkgs
                .into_iter()
                .map(|pkg| SystemCpe {
                    cpe: CpeEntry {
                        part: CpePart::Application,
                        vendor: String::new(),
                        product: pkg.name.to_lowercase().replace("-", "_"),
                        version: Some(pkg.version),
                        raw: String::new(), // Generated later
                    },
                    source: CpeSource::PackageManager(self.name().to_string()),
                })
                .collect(),
            Err(e) => {
                error!("Failed to decode `pip list` results: {}", e);
                vec![]
            }
        }
    }
}
