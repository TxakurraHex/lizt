use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cve {
    pub id: String,
    pub description: Option<String>,
    pub severity: Option<Severity>,
    pub cvss_score: Option<f32>,
    pub published: Option<OffsetDateTime>,
    pub last_modified: Option<OffsetDateTime>,
    pub is_kev: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    None,
}