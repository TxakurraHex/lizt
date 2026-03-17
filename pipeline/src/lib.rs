use common::cve::Cve;
use common::finding_record::FindingRecord;
use common::scan::{Scan, ScanStatus};
use common::symbol::Symbol;
use db::scans_table;
use io_inventory::inventory::{Inventory, Source};
use io_inventory::sources::{
    dpkg_inv_source::DpkgSource, linux_kernel_inv_source::LinuxKernelSource,
    pip_inv_source::PipSource, ubuntu_inv_source::UbuntuSource,
};
use io_nvd::{client::LiztClient, cpe_resolver::CpeResolver};
use io_symbols::{
    extractor::{CveSymbolExtractor, Scraper},
    scrapers::{description::DescriptionScraper, github::GithubScraper, osv::OsvScraper},
};
use log::{debug, error};
use sqlx::PgPool;
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use tokio::sync::broadcast;
use uuid::Uuid;

// -- Errors ------------------------------------------------------------------------------ //

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),

    #[error("scan already running")]
    AlreadyRunning,

    #[error("pipeline stage failed - {stage}: {source}")]
    Stage {
        stage: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

// -- Events ------------------------------------------------------------------------------ //

#[derive(Debug, Clone)]
pub enum ScanEvent {
    Started { scan_id: Uuid },
    Stage { stage: ScanStage, detail: String },
    Complete { scan_id: Uuid },
    Failed { scan_id: Uuid, error: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanStage {
    Inventory,
    CpeResolution,
    CveLookup,
    SymbolExtraction,
    Persisting,
}

impl std::fmt::Display for ScanStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanStage::Inventory => write!(f, "inventory"),
            ScanStage::CpeResolution => write!(f, "cpe_resolution"),
            ScanStage::CveLookup => write!(f, "cve_lookup"),
            ScanStage::SymbolExtraction => write!(f, "symbol_extraction"),
            ScanStage::Persisting => write!(f, "persisting"),
        }
    }
}

// -- Public ------------------------------------------------------------------------------ //

pub fn client_from_env() -> Arc<LiztClient> {
    let nvd_api_key = std::env::var("NVD_API_KEY").ok();
    let github_token = std::env::var("GITHUB_TOKEN").ok();
    Arc::new(LiztClient::new(nvd_api_key, github_token))
}

/// Run the full scan pipeline.
///
/// Creates a scan record, sequences all five stages, updates the record on completion,
/// and broadcasts [`ScanEvent`]s to every active subscriber. Returns the scan ID so
/// callers can link back to the DB record.
///
/// `events` is a broadcast sender; pass `broadcast::channel(32).0` and hand out
/// receivers to whoever needs progress updates. Lagged receivers are silently dropped
/// (the channel uses `broadcast::error::RecvError::Lagged` semantics).
pub async fn run_scan(
    pool: &PgPool,
    client: Arc<LiztClient>,
    events: broadcast::Sender<ScanEvent>,
) -> Result<Uuid, PipelineError> {
    let mut scan = scans_table::insert_scan(pool).await?;
    let scan_id = scan.id;

    // Emit before any stage so subscribers can get the ID
    let _ = events.send(ScanEvent::Started { scan_id });

    let result = execute(pool, client, &events, &scan).await;

    scan.finished_at = Some(chrono::Utc::now());
    scan.status = match &result {
        Ok(_) => ScanStatus::Complete.to_string(),
        Err(_) => ScanStatus::Failed.to_string(),
    };
    // Log error if the scan failed
    if let Err(e) = scans_table::update_scan(pool, &scan).await {
        error!("Failed to update scan record {scan_id}: {e}");
    }

    match &result {
        Ok(_) => {
            let _ = events.send(ScanEvent::Complete { scan_id });
        }
        Err(e) => {
            let _ = events.send(ScanEvent::Failed {
                scan_id,
                error: e.to_string(),
            });
        }
    }

    result.map(|_| scan_id)
}

// -- Internals --------------------------------------------------------------------------- //

fn emit(events: &broadcast::Sender<ScanEvent>, stage: ScanStage, detail: impl Into<String>) {
    // Sending fails only when there are no receivers — that's fine, not an error.
    let _ = events.send(ScanEvent::Stage {
        stage,
        detail: detail.into(),
    });
}

async fn execute(
    pool: &PgPool,
    client: Arc<LiztClient>,
    events: &broadcast::Sender<ScanEvent>,
    scan: &Scan,
) -> Result<(), PipelineError> {
    // Stage 1: inventory
    emit(events, ScanStage::Inventory, "Collecting system inventory…");

    let sources: Vec<Box<dyn Source>> = vec![
        Box::new(PipSource),
        Box::new(DpkgSource),
        Box::new(UbuntuSource),
        Box::new(LinuxKernelSource),
    ];
    let mut inventory = Inventory::new(sources);
    inventory.collect();

    // Stage 2: CPE resolution
    emit(
        events,
        ScanStage::CpeResolution,
        "Resolving CPE entries against NVD…",
    );

    let resolver = CpeResolver::new(Arc::clone(&client));
    let cpe_entries = resolver.resolve_all(&inventory.items).await;
    let cpe_ids = db::cpe_tables::upsert_cpes(pool, &cpe_entries)
        .await
        .map_err(|e| PipelineError::Stage {
            stage: "cpe_resolution",
            source: e.into(),
        })?;

    // Stage 3: CVE lookup
    emit(
        events,
        ScanStage::CveLookup,
        format!(
            "Querying NVD for CVEs across {} CPE entries…",
            cpe_ids.len()
        ),
    );

    let (cves, associations) = fetch_cves(&cpe_ids, &client).await;

    for cve in &cves {
        debug!("CVE: {}", cve.id);
        db::cve_tables::upsert_cve(pool, cve)
            .await
            .map_err(|e| PipelineError::Stage {
                stage: "cve_lookup",
                source: e.into(),
            })?;
    }

    let findings: Vec<FindingRecord> = associations
        .iter()
        .filter_map(|(cpe_id, cve_id)| {
            let cvss = cves.iter().find(|c| c.id == *cve_id)?.cvss_score;
            Some(FindingRecord {
                scan_id: scan.id,
                cpe_id: *cpe_id,
                cve_id: cve_id.clone(),
                cvss_score: cvss,
            })
        })
        .collect();

    db::findings_table::insert_findings(pool, &findings)
        .await
        .map_err(|e| PipelineError::Stage {
            stage: "cve_lookup",
            source: e.into(),
        })?;

    // Stage 4: symbol extraction
    emit(
        events,
        ScanStage::SymbolExtraction,
        format!("Extracting vulnerable symbols from {} CVEs…", cves.len()),
    );

    let symbols = extract_symbols(cves, &client).await;

    // Stage 5: persist symbols
    emit(
        events,
        ScanStage::Persisting,
        format!("Persisting {} symbols to database…", symbols.len()),
    );

    for symbol in &symbols {
        db::symbol_tables::insert_symbol(pool, symbol)
            .await
            .map_err(|e| PipelineError::Stage {
                stage: "persisting",
                source: e.into(),
            })?;
    }

    Ok(())
}

async fn fetch_cves(
    cpe_ids: &HashMap<String, Uuid>,
    client: &LiztClient,
) -> (Vec<Cve>, Vec<(Uuid, String)>) {
    let results =
        futures::future::join_all(cpe_ids.iter().map(|(cpe_string, cpe_uuid)| async move {
            let vulnerabilities = client
                .request_cve_data(cpe_string)
                .await
                .unwrap_or_default();
            let cves: Vec<Cve> = vulnerabilities
                .into_iter()
                .map(|v| Cve::from(v.cve))
                .collect();
            let associations: Vec<(Uuid, String)> =
                cves.iter().map(|c| (*cpe_uuid, c.id.clone())).collect();
            (cves, associations)
        }))
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

async fn extract_symbols(cves: Vec<Cve>, client: &Arc<LiztClient>) -> Vec<Symbol> {
    let scrapers: Vec<Box<dyn Scraper>> = vec![
        Box::new(DescriptionScraper),
        Box::new(GithubScraper::new(Arc::clone(client))),
        Box::new(OsvScraper::new(Arc::clone(client))),
    ];
    let mut extractor = CveSymbolExtractor::new(scrapers);
    extractor.extract_symbols(&cves).await;
    extractor.symbols
}
