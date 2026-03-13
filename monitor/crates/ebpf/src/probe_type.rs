use std::fs::File;
use std::io::{self, BufRead};

pub enum ProbeType {
    KProbe,
    UProbe,
}

pub fn determine(symbol_name: &str) -> io::Result<ProbeType> {
    let file = File::open("/proc/kallsyms")?;
    for line in io::BufReader::new(file).lines() {
        let line = line?;

        // Format: address type name [module]
        let mut parts = line.split_whitespace();
        parts.next(); // address
        parts.next(); // type
        if let Some(name) = parts.next() {
            if name == symbol_name {
                return Ok(ProbeType::KProbe);
            }
        }
    }
    Ok(ProbeType::UProbe)
}
