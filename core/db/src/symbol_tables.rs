use crate::rows::symbol_observation_rows::SymbolObservationRow;
use crate::rows::symbol_rows::{CveSymbolWithActivityRow, CveSymbolWithCpeRow, CveSymbolsRow};
use chrono::{DateTime, Utc};
use common::{symbol::Symbol, symbol_observation::SymbolObservation};
use sqlx::PgPool;

pub async fn insert_symbol(pool: &PgPool, symbol: &Symbol) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        r#"
        INSERT INTO cve_symbols (cve_id, name, source, confidence, source_lang, context, binary_path, probe_type, validated)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (cve_id, name) DO UPDATE SET
            source = EXCLUDED.source,
            confidence = EXCLUDED.confidence,
            source_lang = EXCLUDED.source_lang,
            context = EXCLUDED.context,
            binary_path = EXCLUDED.binary_path,
            probe_type = EXCLUDED.probe_type,
            validated = EXCLUDED.validated
        RETURNING id
        "#,
    )
    .bind(&symbol.cve_id)
    .bind(&symbol.name)
    .bind(&symbol.source)
    .bind(symbol.confidence.to_string())
    .bind(symbol.source_lang.to_string())
    .bind(&symbol.context)
    .bind(&symbol.binary_path)
    .bind(&symbol.probe_type)
    .bind(symbol.validated)
    .fetch_one(pool)
    .await
}

pub async fn get_symbols(pool: &PgPool) -> Result<Vec<Symbol>, sqlx::Error> {
    sqlx::query_as::<_, CveSymbolsRow>("SELECT * FROM cve_symbols")
        .fetch_all(pool)
        .await
        .map(|rows| rows.into_iter().map(Symbol::from).collect())
}

pub async fn get_symbols_with_ids(pool: &PgPool) -> Result<Vec<(i64, Symbol)>, sqlx::Error> {
    sqlx::query_as::<_, CveSymbolWithCpeRow>(
        r#"
            SELECT DISTINCT ON (cs.id)
                cs.id,
                cs.cve_id,
                cs.name,
                cs.source,
                cs.confidence,
                cs.source_lang,
                cs.context,
                cs.binary_path,
                cs.probe_type,
                cs.validated,
                c.product AS cpe_product,
                c.source AS cpe_source
            FROM cve_symbols cs
            LEFT JOIN findings f ON f.cve_id = cs.cve_id
            LEFT JOIN cpes c ON c.id = f.cpe_id
            WHERE cs.validated = TRUE
            ORDER BY cs.id
            "#,
    )
    .fetch_all(pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| {
                let id = row.base.id;
                let symbol = row.base.into_symbol();
                (id, symbol)
            })
            .collect()
    })
}

pub async fn get_symbol_observations(pool: &PgPool) -> Result<Vec<SymbolObservation>, sqlx::Error> {
    sqlx::query_as::<_, SymbolObservationRow>(
        r#"
        SELECT
            cs.id AS cve_symbol_id,
            cs.name AS symbol_name,
            cs.cve_id,
            sa.total_calls,
            sa.distinct_pids,
            sa.last_seen,
            (
                SELECT string_agg(DISTINCT so.process_name, ', ')
                FROM symbol_observations so
                WHERE so.cve_symbol_id = cs.id AND so.process_name IS NOT NULL
            ) AS recent_processes
        FROM cve_symbols cs
        JOIN (
            SELECT
                cve_symbol_id,
                SUM(call_count)::BIGINT AS total_calls,
                COUNT(DISTINCT pid)::BIGINT AS distinct_pids,
                MAX(observed_at) AS last_seen
            FROM symbol_observations
            GROUP BY cve_symbol_id
        ) sa ON sa.cve_symbol_id = cs.id
        ORDER BY sa.total_calls DESC
        LIMIT 200
        "#,
    )
    .fetch_all(pool)
    .await
    .map(|rows| rows.into_iter().map(SymbolObservation::from).collect())
}

pub async fn get_symbols_for_cve_with_activity(
    pool: &PgPool,
    cve_id: &str,
) -> Result<Vec<(i64, Symbol, Option<i64>, Option<i64>, Option<DateTime<Utc>>)>, sqlx::Error> {
    sqlx::query_as::<_, CveSymbolWithActivityRow>(
        r#"
        SELECT
            cs.id,
            cs.cve_id,
            cs.name,
            cs.source,
            cs.confidence,
            cs.source_lang,
            cs.context,
            cs.binary_path,
            cs.probe_type,
            cs.validated,
            sa.total_calls,
            sa.distinct_pids,
            sa.last_seen
        FROM cve_symbols as cs
        LEFT JOIN (
            SELECT
                cve_symbol_id,
                SUM(call_count)::BIGINT AS total_calls,
                COUNT(DISTINCT pid)::BIGINT AS distinct_pids,
                MAX(observed_at) AS last_seen
            FROM symbol_observations
            GROUP BY cve_symbol_id
        ) sa ON sa.cve_symbol_id = cs.id
        WHERE cs.cve_id = $1
        ORDER BY sa.total_calls DESC NULLS LAST
        "#,
    )
    .bind(cve_id)
    .fetch_all(pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| {
                let id = row.base.id;
                let symbol = row.base.into_symbol();
                (
                    id,
                    symbol,
                    row.total_calls,
                    row.distinct_pids,
                    row.last_seen,
                )
            })
            .collect()
    })
}
