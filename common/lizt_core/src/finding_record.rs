use rust_decimal::Decimal;
use uuid::Uuid;

pub struct FindingRecord {
    pub scan_id: Uuid,
    pub cpe_id: Uuid,
    pub cve_id: String,
    pub cvss_score: Option<Decimal>,
}
