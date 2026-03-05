use crate::rows::cve_rows::CveRow;
use lizt_core::cve::Cve;
use sqlx::{PgPool, Postgres, Transaction};

pub async fn upsert_cve(pool: &PgPool, cve: &Cve) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    let existing = sqlx::query_as::<_, CveRow>("SELECT * FROM cves WHERE cve_id = $1")
        .bind(&cve.id)
        .fetch_optional(&mut *tx)
        .await?;

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
    .bind(&cve.refs)
    .bind(cve.cvss_score)
    .bind(&cve.cvss_vector)
    .bind(&cve.cvss_version)
    .bind(cve.published)
    .execute(&mut *tx)
    .await?;

    match existing {
        None => {
            insert_cve_event(&mut tx, &cve.id, "published", None, None).await?;
        }
        Some(old) => {
            if old.cvss_score != cve.cvss_score {
                let old_score = old.cvss_score.map(|s| s.to_string());
                let new_score = cve.cvss_score.map(|s| s.to_string());
                insert_cve_event(
                    &mut tx,
                    &cve.id,
                    "score_changed",
                    old_score.as_deref(),
                    new_score.as_deref(),
                )
                .await?;
            }
            if old.description != cve.descriptions {
                insert_cve_event(
                    &mut tx,
                    &cve.id,
                    "description_changed",
                    old.description.as_deref(),
                    cve.descriptions.as_deref(),
                )
                .await?;
            }
        }
    }

    tx.commit().await
}

async fn insert_cve_event(
    tx: &mut Transaction<'_, Postgres>,
    cve_id: &str,
    event: &str,
    old_value: Option<&str>,
    new_value: Option<&str>,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        r#"
        INSERT INTO cve_events (cve_id, event, old_value, new_value)
        VALUES ($1, $2, $3, $4)
        RETURNING id
        "#,
    )
    .bind(cve_id)
    .bind(event)
    .bind(old_value)
    .bind(new_value)
    .fetch_one(&mut **tx)
    .await
}

pub async fn insert_cve_cpes(
    pool: &PgPool,
    cve: &Cve,
) -> Result<Vec<i64>, Box<dyn std::error::Error>> {
    let mut inserted_ids = vec![];
    if let Some(cpes) = &cve.cpes {
        for cpe in cpes {
            match sqlx::query_scalar(
                r#"
                INSERT INTO cve_cpes (cve_id, cpe, vulnerable, version_start_including, version_start_excluding, version_end_including, version_end_excluding)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                RETURNING id
                "#
            )
                .bind(&cve.id)
                .bind(cpe.cpe.to_cpe_string())
                .bind(cpe.vulnerable)
                .bind(&cpe.version_start_including)
                .bind(&cpe.version_start_excluding)
                .bind(&cpe.version_end_including)
                .bind(&cpe.version_end_excluding)
                .fetch_one(pool)
                .await {
                Ok(id) => inserted_ids.push(id),
                Err(e) => return Err(e.into()),
            }
        }
    }

    Ok(inserted_ids)
}

pub async fn get_all_cves(pool: &PgPool) -> Result<Vec<Cve>, Box<dyn std::error::Error>> {
    let rows = sqlx::query_as::<_, CveRow>("SELECT * FROM cves")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(Cve::from).collect())
}
