use crate::rows::cpe_rows::CpeRow;
use crate::rows::inventory_entry_rows::InventoryEntryRow;
use common::cpe::CpeEntry;
use common::inventory_entry::InventoryEntry;
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

pub async fn upsert_cpe(pool: &PgPool, cpe: &CpeEntry) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar(
        r#"
        INSERT INTO cpes (name, product, vendor, version, source, cpe, cpe_confidence)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (name, product) DO UPDATE SET
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
    .fetch_one(pool)
    .await
}

pub async fn upsert_cpes(
    pool: &PgPool,
    cpes: &[CpeEntry],
) -> Result<HashMap<String, Uuid>, sqlx::Error> {
    let pairs = futures::future::join_all(cpes.iter().map(|cpe| async move {
        let uuid = upsert_cpe(pool, cpe).await?;
        Ok::<(String, Uuid), sqlx::Error>((cpe.cpe.to_cpe_string(), uuid))
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;

    Ok(pairs.into_iter().collect())
}

pub async fn get_all(pool: &PgPool) -> Result<Vec<CpeEntry>, sqlx::Error> {
    let rows = sqlx::query_as::<_, CpeRow>("SELECT * FROM cpes")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(CpeEntry::from).collect())
}

pub async fn get_inventory_entries(pool: &PgPool) -> Result<Vec<InventoryEntry>, sqlx::Error> {
    sqlx::query_as::<_, InventoryEntryRow>(
        r#"
        SELECT
            c.name,
            c.product,
            c.vendor,
            c.version,
            c.source,
            c.cpe,
            c.cpe_confidence,
            COUNT(DISTINCT f.cve_id) AS cve_count,
            c.last_seen
        FROM cpes c
        LEFT JOIN findings f ON f.cpe_id = c.id
        GROUP BY c.id
        ORDER BY cve_count DESC NULLS LAST, c.product ASC
        "#,
    )
    .fetch_all(pool)
    .await
    .map(|rows| rows.into_iter().map(InventoryEntry::from).collect())
}
