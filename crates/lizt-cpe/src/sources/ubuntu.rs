use crate::cpe::{CpeEntry, CpePart, CpeSource, SystemCpe};
use crate::inventory::Source;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use tracing::error;

pub struct UbuntuSource;

impl Source for UbuntuSource {
    fn name(&self) -> &str {
        "ubuntu"
    }

    fn collect(&self) -> Vec<SystemCpe> {
        let mut linux_inventory = Vec::new();
        let Ok(configs) = parse_os_release_file("/etc/os-release") else {
            return linux_inventory;
        };

        if let Some(os_release_info) = os_to_cpe(&configs) {
            linux_inventory.push(SystemCpe {
                cpe: os_release_info,
                source: CpeSource::OsInfo(self.name().to_string()),
            });
        } else {
            error!("Unable to parse configs from /etc/os-release file");
        }

        linux_inventory
    }
}
fn os_to_cpe(os_release_conf: &HashMap<String, String>) -> Option<CpeEntry> {
    match os_release_conf.get("NAME")?.to_lowercase().as_str() {
        "ubuntu" => Some(CpeEntry {
            part: CpePart::OperatingSystem,
            vendor: "canonical".to_string(),
            product: "ubuntu_linux".to_string(),
            version: os_release_conf.get("VERSION_ID").cloned(),
            raw: String::new(),
        }),
        _ => None
    }
}

fn parse_os_release_file(path: &str) -> io::Result<HashMap<String, String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut config = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with("#") {
            continue;
        }

        if let Some((key, value)) = line.split_once("=") {
            let key = key.trim().to_string();
            let value = value.trim().trim_matches('"').to_string();
            config.insert(key, value);
        }
    }

    Ok(config)
}
