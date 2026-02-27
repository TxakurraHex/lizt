use chrono::{DateTime, Utc};
use lizt_core::cve::{CpeMatch, Cve, CvssInfo};
use lizt_core::inventory_item::CpeEntry;
use sqlx::FromRow;

#[derive(Debug, FromRow)]
pub struct CveRow {
    pub cve_id: String,
    pub description: Option<String>,
    pub references: Option<Vec<String>>,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub cvss_version: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
pub struct CveCpeRow {
    pub id: i64,
    pub cve_id: String,
    pub cpe: String,
    pub vulnerable: bool,
    pub version_start_including: Option<String>,
    pub version_start_excluding: Option<String>,
    pub version_end_including: Option<String>,
    pub version_end_excluding: Option<String>,
}

#[derive(Debug, FromRow)]
pub struct CveEventRow {
    pub id: i64,
    pub cve_id: String,
    pub event: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub occurred_at: DateTime<Utc>,
}

impl From<CveRow> for Cve {
    fn from(row: CveRow) -> Self {
        Cve {
            id: row.cve_id.clone(),
            descriptions: row.description.clone(),
            published: row.published_at,
            references: row.references.clone(),
            cvss: row.cvss(),
            cpes: None, // Fetched separately, from another table
        }
    }
}

impl From<CveCpeRow> for CpeMatch {
    fn from(row: CveCpeRow) -> Self {
        CpeMatch {
            cpe_entry: CpeEntry::from_cpe_string(&row.cpe),
            vulnerable: row.vulnerable,
            version_start_including: row.version_start_including,
            version_start_excluding: row.version_start_excluding,
            version_end_including: row.version_end_including,
            version_end_excluding: row.version_end_excluding,
        }
    }
}

impl CveRow {
    pub fn cvss(&self) -> Option<CvssInfo> {
        match (&self.cvss_score, &self.cvss_vector, &self.cvss_version) {
            (Some(score), Some(vector), Some(version)) => Some(CvssInfo {
                score: *score,
                vector: vector.clone(),
                version: version.clone(),
            }),
            _ => None,
        }
    }
}
