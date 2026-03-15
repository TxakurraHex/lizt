use crate::rows::finding_summary_rows::FindingSummaryRow;
use common::finding_record::FindingRecord;
use common::finding_summary::FindingSummary;
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

pub async fn get_finding_summaries(pool: &PgPool) -> Result<Vec<FindingSummary>, sqlx::Error> {
    sqlx::query_as::<_, FindingSummaryRow>(
        r#"
        SELECT
            f.id,
            f.scan_id,
            f.cve_id,
            c.name AS cpe_name,
            c.product AS cpe_product,
            cv.description,
            f.cvss_score,
            cv.cvss_version,
            f.kev_listed,
            f.symbol_present,
            f.symbol_called,
            f.rank_score
        FROM findings f
        JOIN cpes c ON c.id = f.cpe_id
        JOIN cves cv ON cv.cve_id = f.cve_id
        ORDER BY f.rank_score DESC NULLS LAST
        LIMIT 500
        "#,
    )
    .fetch_all(pool)
    .await
    .map(|rows| rows.into_iter().map(FindingSummary::from).collect())
}
