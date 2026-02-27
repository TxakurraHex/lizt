pub mod findings;
pub mod packages;
pub mod rows;
pub mod scans;
pub mod symbols;

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

pub async fn connect() -> Result<PgPool, Box<dyn std::error::Error>> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&std::env::var("DATABASE_URL")?)
        .await?;

    sqlx::migrate!("../../migrations").run(&pool).await?;

    Ok(pool)
}

pub async fn reset() -> Result<(), Box<dyn std::error::Error>> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&std::env::var("ADMINDB_URL")?)
        .await?;

    let db_name = std::env::var("DATABASE_NAME")?;

    // Remove old database
    sqlx::query(&format!("DROP DATABASE IF EXISTS {db_name}"))
        .execute(&pool)
        .await?;

    // Create new iteration of database
    sqlx::query(&format!("CREATE DATABASE {db_name}"))
        .execute(&pool)
        .await?;

    pool.close().await;

    // Re-run migrations
    let fresh_pool = connect().await?;
    fresh_pool.close().await;

    Ok(())
}
