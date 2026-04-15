use crate::rows::finding_summary_rows::FindingSummaryRow;
use common::finding_record::FindingRecord;
use common::finding_summary::FindingSummary;
use sqlx::PgPool;
use uuid::Uuid;

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

pub async fn update_symbol_flags(pool: &PgPool, scan_id: &Uuid) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE findings f SET
            symbol_present = EXISTS (
                SELECT 1 FROM cve_symbols cs
                WHERE cs.cve_id = f.cve_id AND cs.validated = true
            ),
            symbol_called = EXISTS (
                SELECT 1 FROM cve_symbols cs
                JOIN symbol_observations so ON so.cve_symbol_id = cs.id
                WHERE cs.cve_id = f.cve_id AND cs.validated = true
            ),
            updated_at = NOW()
        WHERE f.scan_id = $1
        "#,
    )
    .bind(scan_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

pub async fn compute_rank_scores(pool: &PgPool, scan_id: &Uuid) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE findings f SET
            rank_score = compute_rank_score(
                f.cvss_score,
                cv.epss_score,
                f.kev_listed,
                COALESCE(f.symbol_called, false),
                COALESCE(f.symbol_present, false)
            ),
            updated_at = NOW()
        FROM cves cv
        WHERE cv.cve_id = f.cve_id
          AND f.scan_id = $1
        "#,
    )
    .bind(scan_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
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
            c.version AS cpe_version,
            cv.description,
            f.cvss_score,
            cv.cvss_version,
            f.kev_listed,
            EXISTS (
                SELECT 1 FROM cve_symbols cs
                WHERE cs.cve_id = f.cve_id AND cs.validated = true
            ) AS symbol_present,
            EXISTS (
                SELECT 1 FROM cve_symbols cs
                JOIN symbol_observations so ON so.cve_symbol_id = cs.id
                WHERE cs.cve_id = f.cve_id AND cs.validated = true
            ) AS symbol_called,
            compute_rank_score(
                f.cvss_score,
                cv.epss_score,
                f.kev_listed,
                EXISTS (
                    SELECT 1 FROM cve_symbols cs
                    JOIN symbol_observations so ON so.cve_symbol_id = cs.id
                    WHERE cs.cve_id = f.cve_id AND cs.validated = true
                ),
                EXISTS (
                    SELECT 1 FROM cve_symbols cs
                    WHERE cs.cve_id = f.cve_id AND cs.validated = true
                )
            ) AS rank_score,
            cv.epss_score,
            (SELECT COUNT(*) FROM cve_symbols cs
             JOIN symbol_observations so ON so.cve_symbol_id = cs.id
             WHERE cs.cve_id = f.cve_id AND cs.validated = true
            ) AS symbols_called_count
        FROM findings f
        JOIN cpes c ON c.id = f.cpe_id
        JOIN cves cv ON cv.cve_id = f.cve_id
        ORDER BY rank_score DESC NULLS LAST
        LIMIT 500
        "#,
    )
    .fetch_all(pool)
    .await
    .map(|rows| rows.into_iter().map(FindingSummary::from).collect())
}

pub async fn get_all_finding_summaries(pool: &PgPool) -> Result<Vec<FindingSummary>, sqlx::Error> {
    sqlx::query_as::<_, FindingSummaryRow>(
        r#"
        SELECT
            f.id,
            f.scan_id,
            f.cve_id,
            c.name AS cpe_name,
            c.product AS cpe_product,
            c.version AS cpe_version,
            cv.description,
            f.cvss_score,
            cv.cvss_version,
            f.kev_listed,
            EXISTS (
                SELECT 1 FROM cve_symbols cs
                WHERE cs.cve_id = f.cve_id AND cs.validated = true
            ) AS symbol_present,
            EXISTS (
                SELECT 1 FROM cve_symbols cs
                JOIN symbol_observations so ON so.cve_symbol_id = cs.id
                WHERE cs.cve_id = f.cve_id AND cs.validated = true
            ) AS symbol_called,
            compute_rank_score(
                f.cvss_score,
                cv.epss_score,
                f.kev_listed,
                EXISTS (
                    SELECT 1 FROM cve_symbols cs
                    JOIN symbol_observations so ON so.cve_symbol_id = cs.id
                    WHERE cs.cve_id = f.cve_id AND cs.validated = true
                ),
                EXISTS (
                    SELECT 1 FROM cve_symbols cs
                    WHERE cs.cve_id = f.cve_id AND cs.validated = true
                )
            ) AS rank_score,
            cv.epss_score,
            (SELECT COUNT(*) FROM cve_symbols cs
             JOIN symbol_observations so ON so.cve_symbol_id = cs.id
             WHERE cs.cve_id = f.cve_id AND cs.validated = true
            ) AS symbols_called_count
        FROM findings f
        JOIN cpes c ON c.id = f.cpe_id
        JOIN cves cv ON cv.cve_id = f.cve_id
        ORDER BY rank_score DESC NULLS LAST
        "#,
    )
    .fetch_all(pool)
    .await
    .map(|rows| rows.into_iter().map(FindingSummary::from).collect())
}
