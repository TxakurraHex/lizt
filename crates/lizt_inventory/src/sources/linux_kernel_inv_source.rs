use crate::inventory::Source;
use crate::scraper_proc_runner::run;
use lizt_core::inventory_item::{
    CpeEntry, CpePart, InventoryItem, InventoryItemConfidence, InventorySource,
};
use tracing::error;

pub struct LinuxKernelSource;

impl Source for LinuxKernelSource {
    fn name(&self) -> &str {
        "linux-kernel"
    }

    fn collect(&self) -> Vec<InventoryItem> {
        let mut linux_kernel_inventory = Vec::new();

        if let Some(kernel_info) = get_kernel_info() {
            linux_kernel_inventory.push(InventoryItem {
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
fn get_kernel_info() -> Option<CpeEntry> {
    let raw = run("uname -r")?;
    let kernel_version = raw.trim().split('-').next()?;
    Some(CpeEntry {
        part: CpePart::OperatingSystem,
        vendor: "linux".to_string(),
        product: "linux_kernel".to_string(),
        version: Some(kernel_version.to_string()),
    })
}
