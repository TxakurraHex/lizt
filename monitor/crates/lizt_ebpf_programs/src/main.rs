#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    macros::{kprobe, map, uprobe},
    maps::RingBuf,
    programs::ProbeContext,
};
// Shared ring buffer - userspace reads events from here
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// Set by userspace via EbpfLoader::set_global before loading.
// Each BPF instance corresponds to one symbol; this global tags events
// so the observer knows which symbol fired without needing per-program maps.
#[unsafe(no_mangle)]
static CVE_SYMBOL_ID: i64 = 0;

// Observation event - goes to symbol_observations table
#[repr(C)]
pub struct Event {
    pub pid: u32,
    pub tgid: u32,
    pub comm: [u8; 16],
    pub cve_symbol_id: i64,
}

#[kprobe]
pub fn lizt_kprobe(ctx: ProbeContext) -> u32 {
    match try_probe(ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[uprobe]
pub fn lizt_uprobe(ctx: ProbeContext) -> u32 {
    match try_probe(ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_probe(ctx: ProbeContext) -> Result<(), i64> {
    let cve_symbol_id = unsafe { core::ptr::read_volatile(&CVE_SYMBOL_ID) };
    let mut entry = EVENTS.reserve::<Event>(0).ok_or(1i64)?;
    let event = entry.as_mut_ptr();
    unsafe {
        (*event).pid = ctx.pid();
        (*event).tgid = ctx.tgid();
        (*event).cve_symbol_id = cve_symbol_id;
        (*event).comm = ctx.command().unwrap_or([0u8; 16]);
    }
    entry.submit(0);
    Ok(())
}

#[panic_handler]
fn panic_handler(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
