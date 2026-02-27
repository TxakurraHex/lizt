use lizt_inventory::inventory::{Inventory, Source};
use lizt_inventory::sources::dpkg_inv_source::DpkgSource;
use lizt_inventory::sources::linux_kernel_inv_source::LinuxKernelSource;
use lizt_inventory::sources::pip_inv_source::PipSource;
use lizt_inventory::sources::ubuntu_inv_source::UbuntuSource;

fn main() {
    let sources: Vec<Box<dyn Source>> = vec![
        Box::new(PipSource),
        Box::new(DpkgSource),
        Box::new(UbuntuSource),
        Box::new(LinuxKernelSource),
    ];

    let mut inventory = Inventory::new(sources);
    inventory.collect();

    for item in &inventory.items {
        println!("{:?} -> {}", item.source, item.cpe.to_cpe_string());
    }

    println!(
        "Collected {} items from {} sources",
        inventory.items.len(),
        inventory.sources.len()
    );
}
