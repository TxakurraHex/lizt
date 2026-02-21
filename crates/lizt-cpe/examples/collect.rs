use lizt_cpe::inventory::{Inventory, Source};
use lizt_cpe::sources::dpkg::DpkgSource;
use lizt_cpe::sources::linux_kernel::LinuxKernelSource;
use lizt_cpe::sources::ubuntu::UbuntuSource;
use lizt_cpe::sources::pip::PipSource;

fn main() {
    let sources : Vec<Box<dyn Source>> = vec![
        Box::new(PipSource),
        Box::new(DpkgSource),
        Box::new(UbuntuSource),
        Box::new(LinuxKernelSource),
    ];

    let mut inventory = Inventory::new(sources);
    inventory.collect();

    for item in &inventory.items {
        println!("{:?} -> {}", item.source, item.cpe.match_string());
    }

    println!("Collected {} items from {} sources", inventory.items.len(), inventory.sources.len());
}