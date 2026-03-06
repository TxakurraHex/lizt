use anyhow::{Context, Result};
use aya::maps::{MapData, RingBuf};
use aya::programs::{KProbe, UProbe};
use aya::{Ebpf, EbpfLoader};
use lizt_core::symbol::Symbol;

use crate::probe_type::{self, ProbeType};

static BPF_BYTES: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/lizt_ebpf_programs"));

pub struct LoadedProbe {
    // Kept alive to hold probe attachments. Dropped when the struct is dropped.
    pub _ebpf: Ebpf,
    pub ring_buf: RingBuf<MapData>,
}

pub fn load_probes(symbols: &[(i64, Symbol)]) -> Result<Vec<LoadedProbe>> {
    let mut probes = Vec::new();

    for (cve_symbol_id, symbol) in symbols {
        let mut ebpf = EbpfLoader::new()
            .set_global("CVE_SYMBOL_ID", cve_symbol_id, true)
            .load(BPF_BYTES)
            .with_context(|| format!("failed to load BPF object for {}", symbol.name))?;

        match probe_type::determine(&symbol.name, None)
            .with_context(|| format!("failed to determine probe type for {}", symbol.name))?
        {
            ProbeType::KProbe => {
                let program: &mut KProbe = ebpf
                    .program_mut("lizt_kprobe")
                    .context("lizt_kprobe program not found")?
                    .try_into()?;
                program.load()?;
                program
                    .attach(&symbol.name, 0)
                    .with_context(|| format!("failed to attach kprobe to {}", symbol.name))?;
            }
            ProbeType::UProbe { binary_path } => {
                let program: &mut UProbe = ebpf
                    .program_mut("lizt_uprobe")
                    .context("lizt_uprobe program not found")?
                    .try_into()?;
                program.load()?;
                program
                    .attach(Some(&symbol.name), 0, &binary_path, None)
                    .with_context(|| format!("failed to attach uprobe to {}", symbol.name))?;
            }
        }

        let map = ebpf.take_map("EVENTS").context("EVENTS map not found")?;
        let ring_buf = RingBuf::try_from(map)?;

        probes.push(LoadedProbe {
            _ebpf: ebpf,
            ring_buf,
        });
    }

    Ok(probes)
}
