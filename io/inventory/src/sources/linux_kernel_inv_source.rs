use crate::inventory::Source;
use common::cpe::{Cpe, CpeEntry, CpePart, InventoryItemConfidence, InventorySource};
use common::process_runner::run;
use tracing::error;

pub struct LinuxKernelSource;

impl Source for LinuxKernelSource {
    fn name(&self) -> &str {
        "linux-kernel"
    }

    fn collect(&self) -> Vec<CpeEntry> {
        let mut linux_kernel_inventory = Vec::new();

        if let Some(kernel_info) = get_kernel_info() {
            linux_kernel_inventory.push(CpeEntry {
                cpe: kernel_info,
                source: InventorySource::OsInfo(self.name().to_string()),
                cpe_confidence: InventoryItemConfidence::High,
            });
        } else {
            error!("Unable to parse kernel info from uname -r");
        }

        linux_kernel_inventory
    }
}
fn get_kernel_info() -> Option<Cpe> {
    let raw = run("uname -r")?;
    let kernel_version = raw.trim().split('-').next()?;
    Some(Cpe {
        name: "linux_kernel".to_string(),
        part: CpePart::OperatingSystem,
        vendor: "linux".to_string(),
        product: "linux_kernel".to_string(),
        version: Some(kernel_version.to_string()),
    })
}
