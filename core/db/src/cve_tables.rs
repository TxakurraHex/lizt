use crate::rows::cve_rows::{CveRow, CveWithKevRow};
use common::cve::Cve;
use sqlx::PgPool;

pub async fn upsert_cve(pool: &PgPool, cve: &Cve) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO cves (cve_id, description, refs, cvss_score, cvss_vector, cvss_version, published_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (cve_id) DO UPDATE SET
                last_seen = NOW(),
                description = EXCLUDED.description,
                refs = EXCLUDED.refs,
                cvss_score = EXCLUDED.cvss_score,
                cvss_vector = EXCLUDED.cvss_vector,
                cvss_version = EXCLUDED.cvss_version,
                published_at = EXCLUDED.published_at",
    )
    .bind(&cve.id)
    .bind(&cve.descriptions)
    .bind(cve.refs.as_ref().map(sqlx::types::Json))
    .bind(cve.cvss_score)
    .bind(&cve.cvss_vector)
    .bind(&cve.cvss_version)
    .bind(cve.published)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_all_cves(pool: &PgPool) -> Result<Vec<Cve>, Box<dyn std::error::Error>> {
    let rows = sqlx::query_as::<_, CveRow>("SELECT * FROM cves")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(Cve::from).collect())
}

pub async fn get_cve_with_kev(
    pool: &PgPool,
    cve_id: &str,
) -> Result<Option<(Cve, bool)>, sqlx::Error> {
    sqlx::query_as::<_, CveWithKevRow>(
        r#"
        SELECT
            cv.cve_id,
            cv.description,
            cv.cvss_score,
            cv.cvss_vector,
            cv.cvss_version,
            cv.published_at,
            cv.first_seen,
            cv.last_seen,
            (k.cve_id IS NOT NULL) AS kev_listed
        FROM cves cv
        LEFT JOIN kev k ON k.cve_id = cv.cve_id
        WHERE cv.cve_id = $1
        "#,
    )
    .bind(cve_id)
    .fetch_optional(pool)
    .await
    .map(|opt| {
        opt.map(|row| {
            let cve = Cve {
                id: row.cve_id,
                descriptions: row.description,
                published: row.published_at,
                refs: None,
                cvss_score: row.cvss_score,
                cvss_vector: row.cvss_vector,
                cvss_version: row.cvss_version,
                cpes: None,
            };
            (cve, row.kev_listed)
        })
    })
}
