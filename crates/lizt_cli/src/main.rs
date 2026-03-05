use clap::{Parser, Subcommand};
use lizt_core::cpe::CpeEntry;
use lizt_core::cve::Cve;
use lizt_core::scan::ScanStatus;
use lizt_core::symbol::Symbol;
use lizt_inventory::inventory::{Inventory, Source};
use lizt_inventory::sources::dpkg_inv_source::DpkgSource;
use lizt_inventory::sources::linux_kernel_inv_source::LinuxKernelSource;
use lizt_inventory::sources::pip_inv_source::PipSource;
use lizt_inventory::sources::ubuntu_inv_source::UbuntuSource;
use lizt_rest::cpe_resolver::CpeResolver;
use lizt_rest::rest_client::LiztRestClient;
use lizt_symbols::scrapers::description_scraper::DescriptionScraper;
use lizt_symbols::scrapers::github_scraper::GithubScraper;
use lizt_symbols::symbol_extractor::{CveSymbolExtractor, Scraper};
use log::{debug, error, info};
use sqlx::types::chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "lizt",
    version = "0.0.1",
    about = "Reachability-aware vulnerability analysis tool"
)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the pipeline from start to finish
    Scan,
    Reset {
        #[arg(long)]
        confirm: bool, // require --confirm to prevent accidentally clearing db
    },
    /// Collect/refresh inventory for current system
    Inventory,
    /// Get symbols from CVEs
    Symbols {
        #[clap(short, long)]
        cve_id: Option<String>,
    },
    /// Generate or update vulnerability rankings
    Rank,
    /// Update configurations
    Configure,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    log4rs::init_file("conf/log4rs.yaml", Default::default())?;

    let pool = lizt_db::connect().await?;

    let cli = Cli::parse();

    let rest_client: std::cell::OnceCell<Arc<LiztRestClient>> = std::cell::OnceCell::new();
    let client = || rest_client.get_or_init(get_rest_client);

    match cli.command {
        Commands::Scan => {
            let mut current_scan = lizt_db::scans_table::insert_scan(&pool).await?;

            let result: Result<(), Box<dyn std::error::Error>> = async {
                let inventory = get_inventory();
                for cpe in &inventory.items {
                    debug!("{}", cpe.cpe.to_cpe_string());
                }

                let resolver = CpeResolver::new(Arc::clone(client()));
                let cpe_entries = resolver.resolve_all(&inventory.items).await;
                lizt_db::cpe_tables::upsert_cpes(&pool, &cpe_entries, &current_scan.id).await?;

                let cves = get_cves(cpe_entries, client()).await;
                for cve in &cves {
                    debug!("CVE: {}", cve.id);
                    lizt_db::cve_tables::upsert_cve(&pool, cve).await?;
                    lizt_db::cve_tables::insert_cve_cpes(&pool, cve).await?;
                }

                let symbols = extract_symbols(cves, Arc::clone(client())).await;
                error!("Extracted {} symbols", symbols.len());
                Ok(())
            }
            .await;

            current_scan.finished_at = Some(Utc::now());
            current_scan.status = if result.is_ok() {
                ScanStatus::Complete.to_string()
            } else {
                ScanStatus::Failed.to_string()
            };
            lizt_db::scans_table::update_scan(&pool, &current_scan).await?;
            result?;
        }
        Commands::Reset { confirm } => {
            if !confirm {
                error!("Pass --confirm to reset the database. WARNING - this is irreversible");
                std::process::exit(1);
            }
        }
        Commands::Inventory => {
            let result: Result<(), Box<dyn std::error::Error>> = async {
                let inventory = get_inventory();

                let resolver = CpeResolver::new(Arc::clone(client()));
                let cpe_entries = resolver.resolve_all(&inventory.items).await;
                lizt_db::cpe_tables::upsert_cpes(&pool, &cpe_entries, &current_scan.id).await?;
                Ok(())
            }
            .await;
            result?;
        }
        Commands::Symbols { cve_id } => {
            if let Some(cve_id) = cve_id {
                let symbols =
                    extract_symbols(get_cve_by_id(&cve_id, client()).await, Arc::clone(client()))
                        .await;

                error!("Extracted {} symbols", symbols.len());
                for symbol in &symbols {
                    debug!("{:?}", symbol);
                }
            } else {
                let result: Result<(), Box<dyn std::error::Error>> = async {
                    let cves = lizt_db::cve_tables::get_all_cves(&pool).await?;

                    let symbols = extract_symbols(cves, Arc::clone(client())).await;
                    error!("Extracted {} symbols", symbols.len());
                    for symbol in &symbols {
                        lizt_db::symbol_tables::insert_symbol(&pool, symbol).await?;
                    }

                    Ok(())
                }
                .await;
                result?;
            }
        }
        Commands::Rank => debug!("Rank"),
        Commands::Configure => debug!("Configure"),
    }

    Ok(())
}

fn get_rest_client() -> Arc<LiztRestClient> {
    let nvd_api_key = std::env::var("NVD_API_KEY").ok();
    let github_token = std::env::var("GITHUB_TOKEN").ok();
    Arc::new(LiztRestClient::new(nvd_api_key, github_token))
}

fn get_inventory() -> Inventory {
    let sources: Vec<Box<dyn Source>> = vec![
        Box::new(PipSource),
        Box::new(DpkgSource),
        Box::new(UbuntuSource),
        Box::new(LinuxKernelSource),
    ];

    let mut inventory = Inventory::new(sources);
    inventory.collect();

    inventory
}

async fn get_cves(cpe_entries: Vec<CpeEntry>, rest_client: &LiztRestClient) -> Vec<Cve> {
    let cpe_strings: Vec<String> = cpe_entries
        .into_iter()
        .map(|cpe_entry| cpe_entry.cpe.to_cpe_string())
        .collect();
    for entry in &cpe_strings {
        debug!("[get_cves] CPE: {}", entry);
    }
    let results = futures::future::join_all(
        cpe_strings
            .iter()
            .map(|cpe_string| rest_client.request_cve_data(cpe_string)),
    )
    .await;

    let mut all_cves: HashMap<String, Cve> = HashMap::new();
    for vulnerabilities in results.into_iter().flatten() {
        for vulnerability in vulnerabilities {
            let cve = Cve::from(vulnerability.cve);
            debug!("Added CVE: {}", cve.id);
            all_cves.insert(cve.id.clone(), cve);
        }
    }
    all_cves.into_values().collect()
}

async fn get_cve_by_id(cve_id: &str, rest_client: &LiztRestClient) -> Vec<Cve> {
    let mut cves: HashMap<String, Cve> = HashMap::new();
    debug!("Requesting CVE: {}", cve_id);
    if let Some(vulnerabilities) = rest_client.request_cve_by_id(cve_id).await {
        info!("Found {} CVEs", vulnerabilities.len());
        for vulnerability in vulnerabilities {
            let cve = Cve::from(vulnerability.cve);
            cves.entry(cve.id.clone()).or_insert(cve);
        }
    }
    cves.into_values().collect()
}

async fn extract_symbols(cves: Vec<Cve>, client: Arc<LiztRestClient>) -> Vec<Symbol> {
    let scrapers: Vec<Box<dyn Scraper>> = vec![
        Box::new(DescriptionScraper),
        Box::new(GithubScraper::new(client)),
    ];
    let mut extractor = CveSymbolExtractor::new(scrapers);
    extractor.extract_symbols(&cves).await;

    extractor.symbols
}
