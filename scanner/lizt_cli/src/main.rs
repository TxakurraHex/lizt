use clap::{Parser, Subcommand};
use lizt_core::cve::Cve;
use lizt_core::finding_record::FindingRecord;
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
use lizt_symbols::scrapers::git_scraper::GithubScraper;
use lizt_symbols::symbol_extractor::{CveSymbolExtractor, Scraper};
use log::{debug, error, info};
use sqlx::types::Uuid;
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
                let resolver = CpeResolver::new(Arc::clone(client()));
                let cpe_entries = resolver.resolve_all(&inventory.items).await;

                let cpe_ids = lizt_db::cpe_tables::upsert_cpes(&pool, &cpe_entries).await?;

                // First part of tuple is all CVEs found
                // Second part is associations between CPEs and CVEs, used in findings table
                let (cves, associations) = get_cves(&cpe_ids, client()).await;
                for cve in &cves {
                    debug!("CVE: {}", cve.id);
                    lizt_db::cve_tables::upsert_cve(&pool, cve).await?;
                }

                let findings: Vec<FindingRecord> = associations
                    .iter()
                    .filter_map(|(cpe_id, cve_id)| {
                        let cvss = cves.iter().find(|cve| cve.id == *cve_id)?.cvss_score;
                        Some(FindingRecord {
                            scan_id: current_scan.id,
                            cpe_id: *cpe_id,
                            cve_id: cve_id.clone(),
                            cvss_score: cvss,
                        })
                    })
                    .collect();

                lizt_db::findings_table::insert_findings(&pool, &findings).await?;

                let symbols = extract_symbols(cves, Arc::clone(client())).await;
                for symbol in &symbols {
                    lizt_db::symbol_tables::insert_symbol(&pool, symbol).await?;
                }
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
                lizt_db::cpe_tables::upsert_cpes(&pool, &cpe_entries).await?;
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

async fn get_cves(
    cpe_string_to_id_map: &HashMap<String, Uuid>,
    rest_client: &LiztRestClient,
) -> (Vec<Cve>, Vec<(Uuid, String)>) {
    let results = futures::future::join_all(cpe_string_to_id_map.iter().map(
        |(cpe_string, cpe_uuid)| async move {
            // Get all vulnerabilities related to the CPE item.
            let vulnerabilities = rest_client
                .request_cve_data(cpe_string)
                .await
                .unwrap_or_default();
            // Map the vulnerability NVD result object to a lizt_core::Cve object
            let cves: Vec<Cve> = vulnerabilities
                .into_iter()
                .map(|nvd_vuln| Cve::from(nvd_vuln.cve))
                .collect();
            // Construct a list of all CVE ID strings to the CPE ID UUID associated with it.
            let associations: Vec<(Uuid, String)> =
                cves.iter().map(|cve| (*cpe_uuid, cve.id.clone())).collect();
            (cves, associations)
        },
    ))
    .await;

    let mut all_cves: HashMap<String, Cve> = HashMap::new();
    let mut all_associations: Vec<(Uuid, String)> = Vec::new();

    for (cves, associations) in results {
        // Deduplicate CVEs
        for cve in cves {
            all_cves.entry(cve.id.clone()).or_insert(cve);
        }
        // There should never be multiple identical CVE to CPE mappings
        // bc they're collected using the CPE strings as an input
        all_associations.extend(associations);
    }
    (all_cves.into_values().collect(), all_associations)
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
