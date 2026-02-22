use serde::{Deserialize, Serialize};
use lizt_core::cpe::{CpeSource, SystemCpe};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SystemInventory {
    pub sources: Vec<CpeSource>,
    pub symbols: Vec<SystemCpe>,
}
