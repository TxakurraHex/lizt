use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use strum::{Display, EnumString};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone, FromRow)]
pub struct Scan {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Display, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum ScanStatus {
    Running,
    Complete,
    Failed,
}
