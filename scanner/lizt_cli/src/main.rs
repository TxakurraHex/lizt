use clap::{Parser, Subcommand};
use inquire::error::InquireError;
use inquire::{Confirm, Select, Text};
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
use lizt_symbols::scrapers::osv_scraper::OsvScraper;
use lizt_symbols::symbol_extractor::{CveSymbolExtractor, Scraper};
use log::{debug, error, info};
use sqlx::types::Uuid;
use sqlx::types::chrono::Utc;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "lizt",
    version = "0.0.1",
    about = "Reachability-aware vulnerability analysis tool"
)]
struct Cli {
    #[clap(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the pipeline from start to finish
    Scan,
    Reset {
        #[arg(long)]
        confirm: bool,
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

// --- Config file helpers ---

fn config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".lizt_config")
}

/// Load KEY=VALUE pairs from ~/.lizt_config into the environment (won't override existing vars).
fn load_config() {
    let path = config_path();
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return;
    };
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            if std::env::var(key).is_err() {
                // Safety: single-threaded at this point (called before tokio spawns tasks)
                unsafe { std::env::set_var(key, value) };
            }
        }
    }
}

// --- Interactive helpers ---

/// One item returned by the interactive menu — either a command to run or a signal to quit.
enum MenuSelection {
    Run(Commands),
    Quit,
}

/// Show the top-level interactive menu and return the chosen action.
fn interactive_menu() -> Result<MenuSelection, Box<dyn std::error::Error>> {
    const SCAN: &str = "Scan       — run full vulnerability scan";
    const INVENTORY: &str = "Inventory  — collect/refresh system inventory";
    const SYMBOLS: &str = "Symbols    — extract symbols from CVEs";
    const RANK: &str = "Rank       — generate vulnerability rankings";
    const CONFIGURE: &str = "Configure  — update API keys and settings";
    const RESET: &str = "Reset      — clear the database";
    const QUIT: &str = "Quit";

    let options = vec![SCAN, INVENTORY, SYMBOLS, RANK, CONFIGURE, RESET, QUIT];

    let result = Select::new("What would you like to do?", options).prompt();

    // Treat Esc / Ctrl-C as quit rather than an error
    let choice = match result {
        Ok(s) => s,
        Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => {
            return Ok(MenuSelection::Quit);
        }
        Err(e) => return Err(e.into()),
    };

    match choice {
        SCAN => Ok(MenuSelection::Run(Commands::Scan)),
        INVENTORY => Ok(MenuSelection::Run(Commands::Inventory)),
        SYMBOLS => {
            let scope_options = vec!["All CVEs in database", "Specific CVE"];
            let scope = Select::new("Extract symbols for:", scope_options).prompt()?;
            if scope == "Specific CVE" {
                let cve_id = Text::new("CVE ID (e.g. CVE-2024-1234):")
                    .with_placeholder("CVE-YYYY-NNNNN")
                    .prompt()?;
                Ok(MenuSelection::Run(Commands::Symbols {
                    cve_id: Some(cve_id),
                }))
            } else {
                Ok(MenuSelection::Run(Commands::Symbols { cve_id: None }))
            }
        }
        RANK => Ok(MenuSelection::Run(Commands::Rank)),
        CONFIGURE => Ok(MenuSelection::Run(Commands::Configure)),
        RESET => Ok(MenuSelection::Run(Commands::Reset { confirm: false })),
        QUIT => Ok(MenuSelection::Quit),
        _ => unreachable!(),
    }
}

/// Interactive configure flow — prompts for API keys and saves to ~/.lizt_config.
fn run_configure() -> Result<(), Box<dyn std::error::Error>> {
    let path = config_path();
    println!("Configure Lizt  (saved to {})", path.display());

    let current_nvd = std::env::var("NVD_API_KEY").unwrap_or_default();
    let current_gh = std::env::var("GITHUB_TOKEN").unwrap_or_default();

    let nvd_key = Text::new("NVD API Key:")
        .with_initial_value(&current_nvd)
        .with_help_message("Raises rate limit from 5 to 50 req/30 s — leave blank to skip")
        .prompt()?;

    let github_token = Text::new("GitHub Token:")
        .with_initial_value(&current_gh)
        .with_help_message("Used to fetch commit diffs for symbol extraction — leave blank to skip")
        .prompt()?;

    let mut lines: Vec<String> = Vec::new();
    if !nvd_key.is_empty() {
        lines.push(format!("NVD_API_KEY={nvd_key}"));
    }
    if !github_token.is_empty() {
        lines.push(format!("GITHUB_TOKEN={github_token}"));
    }

    if lines.is_empty() {
        println!("No changes saved.");
    } else {
        std::fs::write(&path, lines.join("\n") + "\n")?;
        println!("Saved {} setting(s) to {}", lines.len(), path.display());
    }
    Ok(())
}

// --- Entry point ---

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    load_config();
    log4rs::init_file("conf/log4rs.yaml", Default::default())?;

    let cli = Cli::parse();

    let client = get_rest_client();

    // When a subcommand is given on the CLI, run it once and exit.
    // With no subcommand, loop through the interactive menu until Quit.
    if let Some(cmd) = cli.command {
        run_command(cmd, &client).await?;
    } else {
        loop {
            match interactive_menu()? {
                MenuSelection::Quit => break,
                MenuSelection::Run(cmd) => {
                    if let Err(e) = run_command(cmd, &client).await {
                        error!("{e}");
                    }
                }
            }
        }
    }

    Ok(())
}

async fn run_command(
    command: Commands,
    client: &Arc<LiztRestClient>,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::Scan => {
            let pool = lizt_db::connect().await?;
            let mut current_scan = lizt_db::scans_table::insert_scan(&pool).await?;

            let result: Result<(), Box<dyn std::error::Error>> = async {
                let inventory = get_inventory();
                let resolver = CpeResolver::new(Arc::clone(client));
                let cpe_entries = resolver.resolve_all(&inventory.items).await;

                let cpe_ids = lizt_db::cpe_tables::upsert_cpes(&pool, &cpe_entries).await?;

                let (cves, associations) = get_cves(&cpe_ids, client).await;
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

                let symbols = extract_symbols(cves, client).await;
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
            let confirmed = confirm
                || Confirm::new("Reset the database? This is irreversible.")
                    .with_default(false)
                    .prompt()?;

            if !confirmed {
                println!("Reset cancelled.");
                return Ok(());
            }

            lizt_db::reset().await?;
        }

        Commands::Inventory => {
            let pool = lizt_db::connect().await?;
            let inventory = get_inventory();
            let resolver = CpeResolver::new(Arc::clone(client));
            let cpe_entries = resolver.resolve_all(&inventory.items).await;
            lizt_db::cpe_tables::upsert_cpes(&pool, &cpe_entries).await?;
        }

        Commands::Symbols { cve_id } => {
            if let Some(cve_id) = cve_id {
                let symbols = extract_symbols(get_cve_by_id(&cve_id, client).await, client).await;
                error!("Extracted {} symbols", symbols.len());
                for symbol in &symbols {
                    debug!("{:?}", symbol);
                }
            } else {
                let pool = lizt_db::connect().await?;
                let cves = lizt_db::cve_tables::get_all_cves(&pool).await?;
                let symbols = extract_symbols(cves, client).await;
                error!("Extracted {} symbols", symbols.len());
                for symbol in &symbols {
                    lizt_db::symbol_tables::insert_symbol(&pool, symbol).await?;
                }
            }
        }

        Commands::Rank => debug!("Rank"),

        Commands::Configure => run_configure()?,
    }

    Ok(())
}

// --- Helpers ---

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
            let vulnerabilities = rest_client
                .request_cve_data(cpe_string)
                .await
                .unwrap_or_default();
            let cves: Vec<Cve> = vulnerabilities
                .into_iter()
                .map(|nvd_vuln| Cve::from(nvd_vuln.cve))
                .collect();
            let associations: Vec<(Uuid, String)> =
                cves.iter().map(|cve| (*cpe_uuid, cve.id.clone())).collect();
            (cves, associations)
        },
    ))
    .await;

    let mut all_cves: HashMap<String, Cve> = HashMap::new();
    let mut all_associations: Vec<(Uuid, String)> = Vec::new();

    for (cves, associations) in results {
        for cve in cves {
            all_cves.entry(cve.id.clone()).or_insert(cve);
        }
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

async fn extract_symbols(cves: Vec<Cve>, client: &Arc<LiztRestClient>) -> Vec<Symbol> {
    let scrapers: Vec<Box<dyn Scraper>> = vec![
        Box::new(DescriptionScraper),
        Box::new(GithubScraper::new(Arc::clone(client))),
        Box::new(OsvScraper::new(Arc::clone(client))),
    ];
    let mut extractor = CveSymbolExtractor::new(scrapers);
    extractor.extract_symbols(&cves).await;

    extractor.symbols
}
