use clap::{Parser, Subcommand};
use std::collections::HashSet;
use lizt_core::cve::Cve;
use lizt_cpe::inventory::{Inventory, Source};
use lizt_cpe::sources::dpkg::DpkgSource;
use lizt_cpe::sources::linux_kernel::LinuxKernelSource;
use lizt_cpe::sources::pip::PipSource;
use lizt_cpe::sources::ubuntu::UbuntuSource;
use lizt_rest::nvd_cpe::NvdProduct;
use lizt_rest::rest::LiztRestClient;
use lizt_symbols::extractor::{CveSymbolExtractor, Scraper};
use lizt_symbols::scrapers::description::DescriptionScraper;
use lizt_symbols::scrapers::github::GithubScraper;
use lizt_symbols::symbol::Symbol;

#[derive(Parser)]
#[command(name = "lizt", version = "0.0.1", about = "Reachability-aware vulnerability analysis tool")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the pipeline from start to finish
    Start,
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

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Start => {
            let rest_client = get_rest_client();

            let inventory = get_inventory();
            for cpe in &inventory.items {
                println!("{}", cpe.cpe.match_string());
            }

            let cpe_products  = get_products(inventory, &rest_client);
            for product in &cpe_products {
                println!("{}", product.cpe.cpe_name);
            }

            let cves = get_cves(cpe_products, &rest_client);
            for cve in &cves {
                println!("{}", cve.id);
            }

            let symbols = extract_symbols(cves);
            eprintln!("Extracted {} symbols", symbols.len());
        }
        Commands::Inventory => println!("Inventory"),
        Commands::Symbols { cve_id } => {
            if let Some(cve_id) = cve_id {
                let rest_client = get_rest_client();

                println!("Symbols (CVE id: {})", cve_id);
                let symbols = extract_symbols(get_cve_by_id(&cve_id, &rest_client));

                eprintln!("Extracted {} symbols", symbols.len());
                for symbol in &symbols {
                    println!("{:?}", symbol);
                }
            } else {
                println!("Symbols (Current inventory)");
            }
        },
        Commands::Rank => println!("Rank"),
        Commands::Configure => println!("Configure"),
    }
}

fn get_rest_client() -> LiztRestClient {
    let api_key = std::env::var("API_KEY").ok();
    LiztRestClient::new(api_key)
}

fn get_inventory() -> Inventory {
    let sources : Vec<Box<dyn Source>> = vec![
        Box::new(PipSource),
        Box::new(DpkgSource),
        Box::new(UbuntuSource),
        Box::new(LinuxKernelSource),
    ];

    let mut inventory = Inventory::new(sources);
    inventory.collect();

    inventory
}

fn get_products(inventory: Inventory, rest_client: &LiztRestClient) -> Vec<NvdProduct> {
    let mut cpe_products  = Vec::new();
    for cpe_guess in inventory.items {
        println!("Trying cpe guess: {}", cpe_guess.cpe.match_string());
        if let Some(matches) = rest_client.request_cpe_data(&cpe_guess.cpe.match_string()) {
            println!("Got {} product matches", matches.len());
            cpe_products.extend(matches)
        }
    }

    cpe_products
}

fn get_cves(cpe_products: Vec<NvdProduct>, rest_client: &LiztRestClient) -> Vec<Cve> {
    let mut all_cves = HashSet::new();
    for product in cpe_products {
        println!("Trying requesting CVES from cpe: {:?}", product);
        if let Some(vulnerabilities) = rest_client.request_cve_data(&product.cpe.cpe_name) {
            println!("Found {} CVEs", vulnerabilities.len());
            for vulnerability in vulnerabilities {
                all_cves.insert(vulnerability.cve);
            }
        }
    }

    all_cves.into_iter().collect()
}

fn get_cve_by_id(cve_id: &str, rest_client: &LiztRestClient) -> Vec<Cve> {
    let mut cves = HashSet::new();
    println!("Requesting CVE: {}", cve_id);
    if let Some(vulnerabilities) = rest_client.request_cve_by_id(cve_id) {
        println!("Found {} CVEs", cves.len());
        for vulnerability in vulnerabilities {
            cves.insert(vulnerability.cve);
        }
    }
    cves.into_iter().collect()
}

fn extract_symbols(cves: Vec<Cve>) -> Vec<Symbol> {
    let scrapers : Vec<Box<dyn Scraper>> = vec![
        Box::new(DescriptionScraper),
        Box::new(GithubScraper),
    ];
    let mut extractor = CveSymbolExtractor::new(scrapers);
    extractor.extract_symbols(&cves);

    extractor.symbols
}