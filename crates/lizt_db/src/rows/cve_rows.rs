use chrono::{DateTime, Utc};
use lizt_core::cpe::Cpe;
use lizt_core::cve::{Cve, CveCpe};
use rust_decimal::Decimal;
use sqlx::FromRow;

#[derive(Debug, FromRow)]
pub struct CveRow {
    pub cve_id: String,
    pub description: Option<String>,
    pub refs: Option<Vec<String>>,
    pub cvss_score: Option<Decimal>,
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
            refs: row.refs.clone(),
            cvss_score: row.cvss_score.clone(),
            cvss_vector: row.cvss_vector.clone(),
            cvss_version: row.cvss_version.clone(),
            cpes: None, // Fetched separately, from another table
        }
    }
}

impl From<CveCpeRow> for CveCpe {
    fn from(row: CveCpeRow) -> Self {
        CveCpe {
            cpe: Cpe::from_cpe_string(&row.cpe),
            vulnerable: row.vulnerable,
            version_start_including: row.version_start_including,
            version_start_excluding: row.version_start_excluding,
            version_end_including: row.version_end_including,
            version_end_excluding: row.version_end_excluding,
        }
    }
}
