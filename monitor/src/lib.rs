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

    let mut handle: Option<JoinHandle<Result<()>>> = match reload(&pool).await {
        Ok(h) => Some(h),
        Err(e) => {
            warn!("Initial probe load failed (will retry on next scan): {e:#}");
            None
        }
    };

    loop {
        match &mut handle {
            Some(h) => {
                tokio::select! {
                    result = h => {
                        match result {
                            Ok(Ok(())) => info!("Monitor observer finished (no probes active)"),
                            Ok(Err(e)) => warn!("Monitor observer error: {e:#}"),
                            Err(e) => warn!("Monitor observer task failed: {e}"),
                        }
                        handle = None;
                    }
                    event = scan_rx.recv() => {
                        if let Some(new_handle) = handle_event(event, &mut handle, &pool).await {
                            handle = Some(new_handle);
                        }
                    }
                }
            }
            None => {
                let event = scan_rx.recv().await;
                if let Some(new_handle) = handle_event(event, &mut handle, &pool).await {
                    handle = Some(new_handle);
                }
            }
        }
    }
}

/// Process a scan event. Returns a new observer handle on successful reload,
/// or `None` if no reload was needed or reload failed.
async fn handle_event(
    event: Result<ScanEvent, broadcast::error::RecvError>,
    handle: &mut Option<JoinHandle<Result<()>>>,
    pool: &PgPool,
) -> Option<JoinHandle<Result<()>>> {
    match event {
        Ok(ScanEvent::Complete { .. }) => {
            info!("Scan complete — reloading eBPF probes");
            if let Some(h) = handle.take() {
                h.abort();
                let _ = h.await;
            }
            match reload(pool).await {
                Ok(h) => Some(h),
                Err(e) => {
                    error!("Failed to reload probes: {e:#}");
                    None
                }
            }
        }
        Err(broadcast::error::RecvError::Closed) => {
            info!("Scan channel closed — monitor shutting down");
            std::process::exit(0);
        }
        _ => None,
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
