use common::finding_record::FindingRecord;
use sqlx::PgPool;

pub async fn insert_findings(pool: &PgPool, findings: &[FindingRecord]) -> Result<(), sqlx::Error> {
    for f in findings {
        sqlx::query(
            r#"
                INSERT INTO findings (scan_id, cpe_id, cve_id, cpe_match, cvss_score)
                VALUES ($1, $2, $3, true, $4)
                ON CONFLICT (scan_id, cpe_id, cve_id) DO NOTHING
                "#,
        )
        .bind(f.scan_id)
        .bind(f.cpe_id)
        .bind(&f.cve_id)
        .bind(f.cvss_score)
        .execute(pool)
        .await?;
    }
    Ok(())
}
