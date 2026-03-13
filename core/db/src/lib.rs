extern crate core;

pub mod cpe_tables;
pub mod cve_tables;
pub mod findings_table;
pub mod rows;
pub mod scans_table;
pub mod symbol_tables;

use log::debug;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

pub async fn connect() -> Result<PgPool, Box<dyn std::error::Error>> {
    let db_url = std::env::var("DATABASE_URL")?;
    debug!("Connecting to database with URL: {db_url}");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await?;

    debug!("Running migrations");
    sqlx::migrate!("../../migrations").run(&pool).await?;
    debug!("Done");

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

    // Grant schema privileges to the app user (required in PostgreSQL 15+)
    let admin_opts = std::env::var("ADMINDB_URL")?
        .parse::<sqlx::postgres::PgConnectOptions>()?
        .database(&db_name);
    let admin_new_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(admin_opts)
        .await?;
    sqlx::query("GRANT ALL ON SCHEMA public TO PUBLIC")
        .execute(&admin_new_pool)
        .await?;
    admin_new_pool.close().await;

    pool.close().await;

    // Re-run migrations
    let fresh_pool = connect().await?;
    fresh_pool.close().await;

    Ok(())
}
