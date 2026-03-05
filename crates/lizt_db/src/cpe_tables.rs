use crate::rows::cpe_rows::CpeRow;
use lizt_core::cpe::CpeEntry;
use log::info;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

pub async fn upsert_cpe(pool: &PgPool, cpe: &CpeEntry, scan_id: &Uuid) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    info!("Upserting CPE: {}", cpe.cpe.to_cpe_string());

    let existing = sqlx::query_as::<_, CpeRow>("SELECT * FROM cpes WHERE name = $1")
        .bind(&cpe.cpe.name)
        .fetch_optional(&mut *tx)
        .await?;
    // "INSERT INTO cpes (name, product, vendor, version, source, cpe, cpe_confidence)\
    //         VALUES ($1, $2, $3, $4, $5, $6, $7)\
    //         ON CONFLICT (name, product, vendor, version) DO UPDATE SET \
    //             last_seen = NOW(),\
    //             source = EXCLUDED.source,\
    //             cpe = EXCLUDED.cpe,\
    //             cpe_confidence = EXCLUDED.cpe_confidence\
    //         RETURNING id",
    let cpe_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO cpes (name, product, vendor, version, source, cpe, cpe_confidence)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (name, product, vendor, version) DO UPDATE SET
            last_seen = NOW(),
            source = EXCLUDED.source,
            cpe = EXCLUDED.cpe,
            cpe_confidence = EXCLUDED.cpe_confidence
        RETURNING id
    "#,
    )
    .bind(&cpe.cpe.name)
    .bind(&cpe.cpe.product)
    .bind(&cpe.cpe.vendor)
    .bind(&cpe.cpe.version)
    .bind(cpe.source.to_string())
    .bind(cpe.cpe.to_cpe_string())
    .bind(cpe.cpe_confidence.to_string())
    .fetch_one(&mut *tx)
    .await?;

    match existing {
        None => {
            insert_cpe_event(&mut tx, cpe_id, scan_id, "added", None).await?;
        }
        Some(old) => {
            if old.version != cpe.cpe.version {
                insert_cpe_event(
                    &mut tx,
                    cpe_id,
                    scan_id,
                    "version_changed",
                    old.version.as_deref(),
                )
                .await?;
            }
        }
    }

    tx.commit().await
}

async fn insert_cpe_event(
    tx: &mut Transaction<'_, Postgres>,
    cpe_id: Uuid,
    scan_id: &Uuid,
    event: &str,
    old_value: Option<&str>,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        r#"
            INSERT INTO cpe_events (cpe_id, scan_id, event, old_value)
            VALUES ($1, $2, $3, $4)
            RETURNING id
            "#,
    )
    .bind(cpe_id)
    .bind(scan_id)
    .bind(event)
    .bind(old_value)
    .fetch_one(&mut **tx)
    .await
}

pub async fn upsert_cpes(
    pool: &PgPool,
    cpes: &[CpeEntry],
    scan_id: &Uuid,
) -> Result<(), sqlx::Error> {
    futures::future::join_all(cpes.iter().map(|cpe| upsert_cpe(pool, cpe, scan_id)))
        .await
        .into_iter()
        .collect::<Result<Vec<()>, _>>()?;
    Ok(())
}

pub async fn get_all(pool: &PgPool) -> Result<Vec<CpeEntry>, sqlx::Error> {
    let rows = sqlx::query_as::<_, CpeRow>("SELECT * FROM cpes")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(CpeEntry::from).collect())
}
