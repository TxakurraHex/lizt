use anyhow::{Context, Result};
use aya::maps::{MapData, RingBuf};
use aya::programs::{KProbe, UProbe};
use aya::{Ebpf, EbpfLoader};
use common::symbol::Symbol;
use log::{error, info};

use crate::probe_type::{self, ProbeType};
use crate::resolver;

static BPF_BYTES: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/ebpf_programs"));

pub struct LoadedProbe {
    // Kept alive to hold probe attachments. Dropped when the struct is dropped.
    pub _ebpf: Ebpf,
    pub ring_buf: RingBuf<MapData>,
}

pub fn load_probes(
    symbols: &[(i64, Symbol, Option<String>, Option<String>)],
) -> Result<Vec<LoadedProbe>> {
    let mut probes = Vec::new();
    let total_probes = symbols.len();

    for (i, (cve_symbol_id, symbol, cpe_product, cpe_source)) in symbols.iter().enumerate() {
        info!("Attempting load {}/{} ({})", i, total_probes, symbol.name);
        let mut ebpf = match EbpfLoader::new()
            .set_global("CVE_SYMBOL_ID", cve_symbol_id, true)
            .load(BPF_BYTES)
        {
            Ok(e) => e,
            Err(err) => {
                error!("failed to load object for {}: {}", symbol.name, err);
                continue;
            }
        };

        let attach_result = (|| -> Result<()> {
            match probe_type::determine(&symbol.name)
                .with_context(|| format!("failed to determine probe type for {}", symbol.name))?
            {
                ProbeType::KProbe => {
                    let program: &mut KProbe = ebpf
                        .program_mut("lizt_kprobe")
                        .context("lizt_kprobe program not found")?
                        .try_into()?;
                    program.load()?;
                    program.attach(&symbol.name, 0).with_context(|| {
                        format!("failed to attach lizt_kprobe to {}", symbol.name)
                    })?;
                }
                ProbeType::UProbe => {
                    let binary_path = resolver::resolve_library(
                        &symbol.name,
                        cpe_product.as_deref(),
                        cpe_source.as_deref(),
                    )
                    .with_context(|| format!("could not resolve library for {}", symbol.name))?;
                    info!(
                        "Resolved library for {}: {}",
                        symbol.name,
                        binary_path.display()
                    );
                    let program: &mut UProbe = ebpf
                        .program_mut("lizt_uprobe")
                        .context("lizt_uprobe program not found")?
                        .try_into()?;
                    program.load()?;
                    program
                        .attach(Some(&symbol.name), 0, &binary_path, None)
                        .with_context(|| {
                            format!("failed to attach lizt_uprobe to {}", symbol.name)
                        })?;
                    info!("Successfully attached lizt_uprobe  to {}", symbol.name);
                }
            }
            Ok(())
        })();
        if let Err(err) = attach_result {
            error!("failed to attach probe for {}: {:#}", symbol.name, err);
            continue;
        }

        let map = match ebpf.take_map("EVENTS").context("EVENTS map not found") {
            Ok(m) => m,
            Err(err) => {
                error!("failed to get EVENTS map for {}: {:#}", symbol.name, err);
                continue;
            }
        };
        let ring_buf = match RingBuf::try_from(map) {
            Ok(r) => r,
            Err(err) => {
                error!("failed to create ring buf for {}: {:#}", symbol.name, err);
                continue;
            }
        };

        probes.push(LoadedProbe {
            _ebpf: ebpf,
            ring_buf,
        });
    }

    Ok(probes)
}
