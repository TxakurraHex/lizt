use lizt_core::cpe::{CpeEntry, CpePart, CpeSource, SystemCpe};
use crate::inventory::Source;
use crate::runner::run;

pub struct DpkgSource;

impl Source for DpkgSource {
    fn name(&self) -> &str {
        "dpkg"
    }

    fn collect(&self) -> Vec<SystemCpe> {
        let Some(out) = run("dpkg-query -W -f='${Package}\\t${Version}\\n'") else {
            return vec![];
        };

        out.lines()
            .filter_map(|line| {
                let (product, version) = line.split_once('\t')?;
                Some(SystemCpe {
                    cpe: CpeEntry {
                        part: CpePart::Application,
                        vendor: String::new(),
                        product: product.to_lowercase().replace("-", "_"),
                        version: Some(version.to_string()),
                    },
                    source: CpeSource::PackageManager(self.name().to_string()),
                })
            })
            .collect()
    }
}
