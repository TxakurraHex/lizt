use crate::rows::symbol_observation_rows::SymbolObservationRow;
use crate::rows::symbol_rows::{CveSymbolWithCpeRow, CveSymbolsRow};
use common::{
    symbol::{SourceLang, Symbol, SymbolConfidence},
    symbol_observation::SymbolObservation,
};
use sqlx::PgPool;
use std::str::FromStr;

pub async fn insert_symbol(pool: &PgPool, symbol: &Symbol) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        r#"
        INSERT INTO cve_symbols (cve_id, name, source, confidence, source_lang, context)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (cve_id, name) DO UPDATE SET
            source = EXCLUDED.source,
            confidence = EXCLUDED.confidence,
            source_lang = EXCLUDED.source_lang,
            context = EXCLUDED.context
        RETURNING id
        "#,
    )
    .bind(&symbol.cve_id)
    .bind(&symbol.name)
    .bind(&symbol.source)
    .bind(symbol.confidence.to_string())
    .bind(symbol.source_lang.to_string())
    .bind(&symbol.context)
    .fetch_one(pool)
    .await
}

pub async fn get_symbols(pool: &PgPool) -> Result<Vec<Symbol>, sqlx::Error> {
    sqlx::query_as::<_, CveSymbolsRow>("SELECT * FROM cve_symbols")
        .fetch_all(pool)
        .await
        .map(|rows| rows.into_iter().map(Symbol::from).collect())
}

pub async fn get_symbols_with_ids(
    pool: &PgPool,
) -> Result<Vec<(i64, Symbol, Option<String>, Option<String>)>, sqlx::Error> {
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
                c.product AS cpe_product,
                c.source AS cpe_source
            FROM cve_symbols cs
            LEFT JOIN findings f ON f.cve_id = cs.cve_id
            LEFT JOIN cpes c ON c.id = f.cpe_id
            ORDER BY cs.id
            "#,
    )
    .fetch_all(pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| {
                let cpe_product = row.cpe_product.clone();
                let cpe_source = row.cpe_source.clone();
                let symbol = Symbol {
                    name: row.name,
                    source_lang: SourceLang::from_str(&row.source_lang)
                        .unwrap_or(SourceLang::Unknown),
                    confidence: SymbolConfidence::from_str(&row.confidence)
                        .unwrap_or(SymbolConfidence::Low),
                    cve_id: row.cve_id,
                    source: row.source,
                    context: row.context,
                };
                (row.id, symbol, cpe_product, cpe_source)
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
        JOIN symbol_activity sa ON sa.cve_symbol_id = cs.id
        ORDER BY sa.total_calls DESC
        LIMIT 200
        "#,
    )
    .fetch_all(pool)
    .await
    .map(|rows| rows.into_iter().map(SymbolObservation::from).collect())
}
