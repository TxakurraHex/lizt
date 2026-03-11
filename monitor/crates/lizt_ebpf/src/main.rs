use lizt_ebpf::{loader, observer};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    log4rs::init_file("conf/log4rs.yaml", Default::default())?;
    let pool = lizt_db::connect()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let symbols = lizt_db::symbol_tables::get_symbols_with_ids(&pool).await?;
    let probes = loader::load_probes(&symbols)?;
    observer::observe(probes, &pool).await
}
