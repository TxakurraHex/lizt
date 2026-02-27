use clap::{Parser, Subcommand};
use lizt_core::cve::Cve;
use lizt_core::symbol::Symbol;
use lizt_inventory::inventory::{Inventory, Source};
use lizt_inventory::sources::dpkg_inv_source::DpkgSource;
use lizt_inventory::sources::linux_kernel_inv_source::LinuxKernelSource;
use lizt_inventory::sources::pip_inv_source::PipSource;
use lizt_inventory::sources::ubuntu_inv_source::UbuntuSource;
use lizt_rest::cpe_resolver::CpeResolver;
use lizt_rest::nvd::cpe_response::NvdProduct;
use lizt_rest::rest_client::LiztRestClient;
use lizt_symbols::scrapers::description_scraper::DescriptionScraper;
use lizt_symbols::scrapers::github_scraper::GithubScraper;
use lizt_symbols::symbol_extractor::{CveSymbolExtractor, Scraper};
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
    // lizt_db::connect().await?;

    let cli = Cli::parse();

    let rest_client: std::cell::OnceCell<Arc<LiztRestClient>> = std::cell::OnceCell::new();
    let client = || rest_client.get_or_init(get_rest_client);

    match cli.command {
        Commands::Scan => {
            let inventory = get_inventory();
            for cpe in &inventory.items {
                println!("{}", cpe.cpe.to_cpe_string());
            }

            let resolver = CpeResolver::new(Arc::clone(client()));
            let cpe_products = resolver.resolve_all(&inventory.items).await;
            for product in &cpe_products {
                println!("{}", product.cpe.cpe_name);
            }

            let cves = get_cves(cpe_products, client()).await;
            for cve in &cves {
                println!("{}", cve.id);
            }

            let symbols = extract_symbols(cves, Arc::clone(client())).await;
            eprintln!("Extracted {} symbols", symbols.len());
        }
        Commands::Reset { confirm } => {
            if !confirm {
                eprintln!("Pass --confirm to reset the database. WARNING - this is irreversible");
                std::process::exit(1);
            }
        }
        Commands::Inventory => {
            let inventory = get_inventory();
            for cpe in &inventory.items {
                println!("{}", cpe.cpe.to_cpe_string());
            }

            let resolver = CpeResolver::new(Arc::clone(client()));
            let cpe_products = resolver.resolve_all(&inventory.items).await;
            for product in &cpe_products {
                println!("{}", product.cpe.cpe_name);
            }
        }
        Commands::Symbols { cve_id } => {
            if let Some(cve_id) = cve_id {
                println!("Symbols (CVE id: {})", cve_id);
                let symbols =
                    extract_symbols(get_cve_by_id(&cve_id, client()).await, Arc::clone(client()))
                        .await;

                eprintln!("Extracted {} symbols", symbols.len());
                for symbol in &symbols {
                    println!("{:?}", symbol);
                }
            } else {
                println!("Symbols (Current inventory)");
            }
        }
        Commands::Rank => println!("Rank"),
        Commands::Configure => println!("Configure"),
    }

    Ok(())
}

fn get_rest_client() -> Arc<LiztRestClient> {
    let api_key = std::env::var("API_KEY").ok();
    Arc::new(LiztRestClient::new(api_key))
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

async fn get_cves(cpe_products: Vec<NvdProduct>, rest_client: &LiztRestClient) -> Vec<Cve> {
    let results = futures::future::join_all(
        cpe_products
            .iter()
            .map(|product| rest_client.request_cve_data(&product.cpe.cpe_name)),
    )
    .await;

    let mut all_cves: HashMap<String, Cve> = HashMap::new();
    for vulnerabilities in results.into_iter().flatten() {
        for vulnerability in vulnerabilities {
            if let Ok(cve) = Cve::try_from(vulnerability.cve) {
                all_cves.entry(cve.id.clone()).or_insert(cve);
            }
        }
    }
    all_cves.into_values().collect()
}

async fn get_cve_by_id(cve_id: &str, rest_client: &LiztRestClient) -> Vec<Cve> {
    let mut cves: HashMap<String, Cve> = HashMap::new();
    println!("Requesting CVE: {}", cve_id);
    if let Some(vulnerabilities) = rest_client.request_cve_by_id(cve_id).await {
        println!("Found {} CVEs", vulnerabilities.len());
        for vulnerability in vulnerabilities {
            if let Ok(cve) = Cve::try_from(vulnerability.cve) {
                cves.entry(cve.id.clone()).or_insert(cve);
            }
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
