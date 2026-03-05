use chrono::{DateTime, Utc};
use lizt_core::scan::{Scan, ScanStatus};
use sqlx::PgPool;
use uuid::Uuid;

pub async fn insert_scan(pool: &PgPool) -> Result<Scan, sqlx::Error> {
    sqlx::query_as::<_, Scan>(
        r#"
            INSERT INTO scans (started_at, status)
            VALUES ($1, $2)
            RETURNING *
            "#,
    )
    .bind(Utc::now())
    .bind(ScanStatus::Running.to_string())
    .fetch_one(pool)
    .await
}

pub async fn update_scan(pool: &PgPool, scan: &Scan) -> Result<Scan, sqlx::Error> {
    sqlx::query_as::<_, Scan>(
        "UPDATE scans SET finished_at = $1, status = $2 WHERE id = $3 RETURNING *",
    )
    .bind(scan.finished_at.unwrap_or_else(Utc::now))
    .bind(&scan.status)
    .bind(scan.id)
    .fetch_one(pool)
    .await
}

pub async fn get_scans(pool: &PgPool) -> Result<Vec<Scan>, sqlx::Error> {
    sqlx::query_as::<_, Scan>("SELECT * FROM scans")
        .fetch_all(pool)
        .await
}

pub async fn get_scan(pool: &PgPool, scan_id: &Uuid) -> Result<Scan, sqlx::Error> {
    sqlx::query_as::<_, Scan>("SELECT * FROM scans WHERE id = $1")
        .bind(scan_id)
        .fetch_one(pool)
        .await
}

pub async fn get_scans_between(
    pool: &PgPool,
    start_bound: &DateTime<Utc>,
    end_bound: &DateTime<Utc>,
) -> Result<Vec<Scan>, sqlx::Error> {
    sqlx::query_as::<_, Scan>("SELECT * FROM scans WHERE started_at < $1 AND finished_at > $2")
        .bind(start_bound)
        .bind(end_bound)
        .fetch_all(pool)
        .await
}

pub async fn get_scans_by_status(
    pool: &PgPool,
    status: ScanStatus,
) -> Result<Vec<Scan>, sqlx::Error> {
    sqlx::query_as::<_, Scan>("SELECT * FROM scans WHERE status = $1")
        .bind(status.to_string())
        .fetch_all(pool)
        .await
}
