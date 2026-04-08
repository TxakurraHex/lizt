use clap::{Parser, Subcommand};
use inquire::error::InquireError;
use inquire::{Confirm, Select, Text};
use log::{error, info};
use pipeline::{PipelineError, ScanEvent, client_from_env, run_eval, run_scan};
use std::path::PathBuf;
use tokio::sync::broadcast;

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "lizt-cli",
    version = "0.1.0",
    about = "Reachability-aware vulnerability analysis tool"
)]
struct Cli {
    #[clap(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the full pipeline: inventory → CPE → CVE → symbol extraction
    Scan,
    /// Run full scan pipeline against a fixed evaluation set
    Eval {
        /// Fixture name: sudo, bash, libexpat, openssl, all
        #[arg(long)]
        fixture: String,
    },
    /// Generate or update vulnerability rankings
    Rank,
    /// Drop and recreate the database, then re-run migrations
    Reset {
        #[arg(long)]
        confirm: bool,
    },
    /// Export findings as JSON or CSV
    Export {
        /// Output format: json or csv
        #[arg(long, default_value = "json")]
        format: String,
        /// Output file path (defaults to stdout)
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Interactively set NVD_API_KEY and GITHUB_TOKEN
    Configure,
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    load_config();

    let log_conf_filepath = "/etc/lizt/cli_log4rs.yaml";
    log4rs::init_file(log_conf_filepath, Default::default()).unwrap_or_else(|_| {
        eprintln!("log4rs config ({log_conf_filepath}) not found, using stderr")
    });

    let pool = db::connect().await?;
    let client = client_from_env();

    let command = match Cli::parse().command {
        Some(c) => c,
        None => match interactive_menu()? {
            MenuSelection::Run(c) => c,
            MenuSelection::Quit => return Ok(()),
        },
    };

    match command {
        Commands::Scan => {
            let (tx, mut rx) = broadcast::channel::<ScanEvent>(32);

            let pool_clone = pool.clone();
            let client_clone = client.clone();
            let tx_clone = tx.clone();
            let handle =
                tokio::spawn(async move { run_scan(&pool_clone, client_clone, tx_clone).await });

            loop {
                match rx.recv().await {
                    Ok(ScanEvent::Started { scan_id }) => {
                        info!("Started: [{scan_id}]");
                    }
                    Ok(ScanEvent::Stage { stage, detail }) => {
                        info!("[{stage}] {detail}");
                    }
                    Ok(ScanEvent::Complete { scan_id }) => {
                        info!("Scan complete ({scan_id})");
                        break;
                    }
                    Ok(ScanEvent::Failed { scan_id, error }) => {
                        error!("Scan failed ({scan_id}): {error}");
                        break;
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        error!("Warning: dropped {n} progress events (channel lagged)");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }

            match handle.await? {
                Ok(_) => {}
                Err(PipelineError::AlreadyRunning) => error!("A scan is already running."),
                Err(PipelineError::Db(e)) => return Err(e.into()),
                Err(PipelineError::Stage { stage, source }) => {
                    return Err(format!("stage {stage} failed: {source}").into());
                }
            }
        }

        Commands::Eval { fixture } => {
            let (tx, mut rx) = broadcast::channel::<ScanEvent>(32);

            let pool_clone = pool.clone();
            let client_clone = client.clone();
            let tx_clone = tx.clone();
            let fixture_clone = fixture.clone();
            let handle = tokio::spawn(async move {
                run_eval(&pool_clone, client_clone, &fixture_clone, tx_clone).await
            });

            loop {
                match rx.recv().await {
                    Ok(ScanEvent::Started { scan_id }) => {
                        info!("Started eval ({fixture}): [{scan_id}]");
                    }
                    Ok(ScanEvent::Stage { stage, detail }) => {
                        info!("[{stage}] {detail}");
                    }
                    Ok(ScanEvent::Complete { scan_id }) => {
                        info!("Eval complete ({scan_id})");
                        break;
                    }
                    Ok(ScanEvent::Failed { scan_id, error }) => {
                        error!("Eval failed ({scan_id}): {error}");
                        break;
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        error!("Warning: dropped {n} progress events (channel lagged)");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }

            match handle.await? {
                Ok(_) => {}
                Err(PipelineError::AlreadyRunning) => error!("A scan is already running."),
                Err(PipelineError::Db(e)) => return Err(e.into()),
                Err(PipelineError::Stage { stage, source }) => {
                    return Err(format!("stage {stage} failed: {source}").into());
                }
            }
        }

        Commands::Rank => {
            let scan_id = match db::scans_table::get_latest_scan_id(&pool).await? {
                Some(id) => id,
                None => {
                    error!("No scans found. Run a scan first.");
                    return Ok(());
                }
            };
            info!("Recomputing rankings for scan {scan_id}...");

            let flags = db::findings_table::update_symbol_flags(&pool, &scan_id).await?;
            let ranks = db::findings_table::compute_rank_scores(&pool, &scan_id).await?;
            info!("Updated {flags} symbol flags, recomputed {ranks} rank scores.");
        }

        Commands::Reset { confirm } => {
            let confirmed = confirm
                || Confirm::new("Reset the database? This is irreversible.")
                    .with_default(false)
                    .prompt()?;

            if !confirmed {
                info!("Reset cancelled.");
                return Ok(());
            }

            db::reset().await?;
            info!("Database reset.");
        }

        Commands::Export { format, output } => {
            let findings = db::findings_table::get_all_finding_summaries(&pool).await?;
            let bytes = match format.as_str() {
                "csv" => common::report::to_csv(&findings)
                    .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?,
                _ => common::report::to_json(&findings)
                    .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?,
            };
            match output {
                Some(path) => {
                    std::fs::write(&path, &bytes)?;
                    info!("Report written to {}", path.display());
                }
                None => {
                    use std::io::Write;
                    std::io::stdout().write_all(&bytes)?;
                }
            }
        }

        Commands::Configure => run_configure()?,
    }

    Ok(())
}

// ── Interactive menu ──────────────────────────────────────────────────────────

enum MenuSelection {
    Run(Commands),
    Quit,
}

fn interactive_menu() -> Result<MenuSelection, Box<dyn std::error::Error>> {
    const SCAN: &str = "Scan       — run full vulnerability scan";
    const EVAL: &str = "Eval       — run scan against an evaluation fixture";
    const RANK: &str = "Rank       — generate vulnerability rankings";
    const EXPORT: &str = "Export     — download findings as JSON or CSV";
    const CONFIGURE: &str = "Configure  — update API keys and settings";
    const RESET: &str = "Reset      — clear the database";
    const QUIT: &str = "Quit";

    let choice = match Select::new(
        "What would you like to do?",
        vec![SCAN, EVAL, RANK, EXPORT, CONFIGURE, RESET, QUIT],
    )
    .prompt()
    {
        Ok(s) => s,
        Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => {
            return Ok(MenuSelection::Quit);
        }
        Err(e) => return Err(e.into()),
    };

    Ok(match choice {
        SCAN => MenuSelection::Run(Commands::Scan),
        EVAL => {
            let fixture = Select::new(
                "Choose evaluation fixture:",
                vec!["sudo", "bash", "libexpat", "openssl", "all"],
            )
            .prompt()?;
            MenuSelection::Run(Commands::Eval {
                fixture: fixture.to_string(),
            })
        }
        RANK => MenuSelection::Run(Commands::Rank),
        EXPORT => {
            let format = Select::new("Output format:", vec!["json", "csv"]).prompt()?;
            let path = Text::new("Output file path (leave blank for stdout):")
                .with_default("")
                .prompt()?;
            let output = if path.is_empty() {
                None
            } else {
                Some(PathBuf::from(path))
            };
            MenuSelection::Run(Commands::Export {
                format: format.to_string(),
                output,
            })
        }
        CONFIGURE => MenuSelection::Run(Commands::Configure),
        RESET => MenuSelection::Run(Commands::Reset { confirm: false }),
        QUIT => MenuSelection::Quit,
        _ => unreachable!(),
    })
}

// ── Configure ─────────────────────────────────────────────────────────────────

fn config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".lizt_config")
}

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
        if let Some((key, value)) = line.split_once('=')
            && std::env::var(key).is_err()
        {
            unsafe { std::env::set_var(key, value) };
        }
    }
}

fn run_configure() -> Result<(), Box<dyn std::error::Error>> {
    let path = config_path();
    info!("Configure Lizt  (saved to {})", path.display());

    let nvd_key = Text::new("NVD API Key:")
        .with_initial_value(&std::env::var("NVD_API_KEY").unwrap_or_default())
        .with_help_message("Raises rate limit from 5 to 50 req/30s — leave blank to skip")
        .prompt()?;

    let github_token = Text::new("GitHub Token:")
        .with_initial_value(&std::env::var("GITHUB_TOKEN").unwrap_or_default())
        .with_help_message("Used to fetch commit diffs — leave blank to skip")
        .prompt()?;

    let mut lines = vec![];
    if !nvd_key.is_empty() {
        lines.push(format!("NVD_API_KEY={nvd_key}"));
    }
    if !github_token.is_empty() {
        lines.push(format!("GITHUB_TOKEN={github_token}"));
    }

    std::fs::write(&path, lines.join("\n") + "\n")?;
    info!("Saved to {}", path.display());
    Ok(())
}
