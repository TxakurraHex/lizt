use io_nvd::client::LiztClient;
use pipeline::ScanEvent;
use serde::Serialize;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::{Mutex, broadcast};

#[derive(Clone, Serialize)]
pub struct ScanStageInfo {
    pub scan_id: Uuid,
    pub stage: String,
    pub detail: String,
}

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub client: Arc<LiztClient>,
    pub scan_tx: broadcast::Sender<ScanEvent>,
    pub scan_running: Arc<Mutex<bool>>,
    pub scan_stage: Arc<Mutex<Option<ScanStageInfo>>>,
}
