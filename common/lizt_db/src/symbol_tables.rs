use crate::rows::symbol_rows::CveSymbolsRow;
use lizt_core::symbol::Symbol;
use sqlx::PgPool;

pub async fn insert_symbol(pool: &PgPool, symbol: &Symbol) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        r#"
        INSERT INTO cve_symbols (cve_id, name, source, confidence, symbol_type, context)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (cve_id, name) DO UPDATE SET
            source = EXCLUDED.source,
            confidence = EXCLUDED.confidence,
            symbol_type = EXCLUDED.symbol_type,
            context = EXCLUDED.context
        RETURNING id
        "#,
    )
    .bind(&symbol.cve_id)
    .bind(&symbol.name)
    .bind(&symbol.source)
    .bind(symbol.confidence.to_string())
    .bind(symbol.symbol_type.to_string())
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

pub async fn get_symbols_with_ids(pool: &PgPool) -> Result<Vec<(i64, Symbol)>, sqlx::Error> {
    sqlx::query_as::<_, CveSymbolsRow>("SELECT * FROM cve_symbols")
        .fetch_all(pool)
        .await
        .map(|rows| {
            rows.into_iter()
                .map(|row| (row.id, Symbol::from(row)))
                .collect()
        })
}
