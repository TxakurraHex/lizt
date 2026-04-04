pub mod loader;
pub mod observer;

use anyhow::Result;
use log::{error, info};
use pipeline::ScanEvent;
use sqlx::PgPool;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

/// Spawn the eBPF monitor as a background task.
///
/// Loads probes for current symbols, observes ring buffers, and reloads
/// probes whenever a scan completes (new symbols may have been added).
pub async fn spawn_monitor(pool: PgPool, mut scan_rx: broadcast::Receiver<ScanEvent>) {
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
