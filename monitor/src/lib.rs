pub mod loader;
pub mod observer;

use anyhow::Result;
use log::{error, info, warn};
use pipeline::ScanEvent;
use sqlx::PgPool;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

/// Required Linux capabilities for eBPF probe attachment.
const REQUIRED_CAPS: &[(u32, &str)] = &[
    (39, "CAP_BPF"),
    (38, "CAP_PERFMON"),
    (21, "CAP_SYS_ADMIN"),
    (24, "CAP_SYS_RESOURCE"),
];

/// Check the current process for the capabilities needed to attach eBPF probes.
/// Logs a warning for each missing capability and returns `false` if any are absent.
fn check_capabilities() -> bool {
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(e) => {
            warn!("Could not read /proc/self/status to check capabilities: {e}");
            return false;
        }
    };

    // CapEff is the effective capability set, encoded as a hex bitmask.
    let eff = status
        .lines()
        .find(|l| l.starts_with("CapEff:"))
        .and_then(|l| u64::from_str_radix(l.split_whitespace().last()?, 16).ok())
        .unwrap_or(0);

    let missing: Vec<&str> = REQUIRED_CAPS
        .iter()
        .filter(|(bit, _)| eff & (1u64 << bit) == 0)
        .map(|(_, name)| *name)
        .collect();

    if missing.is_empty() {
        return true;
    }

    warn!(
        "Missing capabilities: {}. eBPF probes will fail to attach. \
         Run as root or grant capabilities with: \
         sudo setcap cap_bpf,cap_perfmon,cap_sys_admin,cap_sys_resource+eip <binary>",
        missing.join(", ")
    );
    false
}

/// Spawn the eBPF monitor as a background task.
///
/// Loads probes for current symbols, observes ring buffers, and reloads
/// probes whenever a scan completes (new symbols may have been added).
pub async fn spawn_monitor(pool: PgPool, mut scan_rx: broadcast::Receiver<ScanEvent>) {
    if !check_capabilities() {
        error!("Monitor will not start — missing required capabilities");
        return;
    }

    let mut handle = match reload(&pool).await {
        Ok(h) => h,
        Err(e) => {
            error!("Monitor failed to start: {e:#}");
            return;
        }
    };

    loop {
        tokio::select! {
            result = &mut handle => {
                error!("Monitor observer exited unexpectedly: {result:?}");
                return;
            }
            event = scan_rx.recv() => {
                match event {
                    Ok(ScanEvent::Complete { .. }) => {
                        info!("Scan complete — reloading eBPF probes");
                        handle.abort();
                        let _ = handle.await;
                        match reload(&pool).await {
                            Ok(h) => handle = h,
                            Err(e) => {
                                error!("Failed to reload probes: {e:#}");
                                return;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                    _ => {}
                }
            }
        }
    }
}

async fn reload(pool: &PgPool) -> Result<JoinHandle<Result<()>>> {
    let symbols = db::symbol_tables::get_symbols_with_ids(pool).await?;
    info!("Loading {} eBPF probes", symbols.len());
    let probes = loader::load_probes(&symbols)?;
    let pool = pool.clone();
    Ok(tokio::spawn(async move {
        observer::observe(probes, &pool).await
    }))
}
