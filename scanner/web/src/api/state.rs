use io_nvd::client::LiztClient;
use pipeline::ScanEvent;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::{Mutex, broadcast};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub client: Arc<LiztClient>,
    pub scan_tx: broadcast::Sender<ScanEvent>,
    pub scan_running: Arc<Mutex<bool>>,
}
