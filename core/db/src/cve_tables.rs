use crate::rows::cve_rows::CveRow;
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
