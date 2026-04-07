use common::cpe::Cpe;
use common::cve::Cve;
use common::finding_record::FindingRecord;
use common::resolved_symbol::SymbolIndex;
use common::scan::{Scan, ScanStatus};
use common::symbol::Symbol;
use db::scans_table;
use io_inventory::fixtures;
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
use log::{debug, error, info};
use rust_decimal::Decimal;
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
    SymbolValidation,
    Persisting,
    EpssFetch,
    Ranking,
}

impl std::fmt::Display for ScanStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanStage::Inventory => write!(f, "inventory"),
            ScanStage::CpeResolution => write!(f, "cpe_resolution"),
            ScanStage::CveLookup => write!(f, "cve_lookup"),
            ScanStage::SymbolExtraction => write!(f, "symbol_extraction"),
            ScanStage::SymbolValidation => write!(f, "symbol_validation"),
            ScanStage::Persisting => write!(f, "persisting"),
            ScanStage::EpssFetch => write!(f, "epss_fetch"),
            ScanStage::Ranking => write!(f, "ranking"),
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

    let _ = events.send(ScanEvent::Started { scan_id });

    emit(
        &events,
        ScanStage::Inventory,
        "Collecting system inventory...",
    );
    info!("Collecting system inventory...");

    let sources: Vec<Box<dyn Source>> = vec![
        Box::new(PipSource),
        Box::new(DpkgSource),
        Box::new(UbuntuSource),
        Box::new(LinuxKernelSource),
    ];
    let mut inventory = Inventory::new(sources);
    inventory.collect();

    let result = execute(pool, client, &events, &scan, inventory).await;

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

/// Run the pipeline against a fixed evaluation fixture instead of the live system inventory.
///
/// Identical to [`run_scan`] except the inventory is built from `fixture_name` and the scan
/// record is tagged with that name so eval runs are distinguishable in the database.
///
/// Valid fixture names: `sudo`, `bash`, `libexpat`, `openssl`, `all`.
pub async fn run_eval(
    pool: &PgPool,
    client: Arc<LiztClient>,
    fixture_name: &str,
    events: broadcast::Sender<ScanEvent>,
) -> Result<Uuid, PipelineError> {
    let mut inventory = match fixture_name {
        "libexpat" => fixtures::libexpat_cve_2022_25236(),
        "openssl" => fixtures::openssl_cve_2022_0778(),
        "zlib" => fixtures::zlib_cve_2022_37434(),
        "all" => fixtures::all_eval_fixtures(),
        other => {
            return Err(PipelineError::Stage {
                stage: "eval",
                source: format!("unknown fixture '{other}'; valid: libexpat, openssl, zlib, all")
                    .into(),
            });
        }
    };
    inventory.collect();

    let mut scan = scans_table::insert_scan(pool).await?;
    let scan_id = scan.id;

    if let Err(e) = db::scans_table::set_fixture_name(pool, &scan_id, fixture_name).await {
        error!("Failed to tag scan {scan_id} with fixture name: {e}");
    }

    let _ = events.send(ScanEvent::Started { scan_id });

    let result = execute(pool, client, &events, &scan, inventory).await;

    scan.finished_at = Some(chrono::Utc::now());
    scan.status = match &result {
        Ok(_) => ScanStatus::Complete.to_string(),
        Err(_) => ScanStatus::Failed.to_string(),
    };
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
    inventory: Inventory,
) -> Result<(), PipelineError> {
    for item in &inventory.items {
        info!("{:?}", item);
    }

    // Stage 2: CPE resolution
    emit(
        events,
        ScanStage::CpeResolution,
        "Resolving CPE entries against NVD...",
    );
    info!("Resolving CPE entries against NVD...");

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
            "Querying NVD for CVEs across {} CPE entries...",
            cpe_ids.len()
        ),
    );
    info!(
        "Querying NVD for CVEs across {} CPE entries...",
        cpe_ids.len()
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

    // Collect CVE IDs before cves is moved into extract_symbols
    let cve_ids: Vec<String> = cves.iter().map(|c| c.id.clone()).collect();

    // Stage 4: symbol extraction
    emit(
        events,
        ScanStage::SymbolExtraction,
        format!("Extracting vulnerable symbols from {} CVEs...", cves.len()),
    );
    info!("Extracting vulnerable symbols from {} CVEs...", cves.len());

    let mut symbols = extract_symbols(cves, &client).await;

    // Stage 5: symbol validation
    emit(
        events,
        ScanStage::SymbolValidation,
        format!(
            "Validating {} symbols against system binaries...",
            symbols.len()
        ),
    );
    info!(
        "Validating {} symbols against system binaries...",
        symbols.len()
    );

    let package_hints: Vec<(String, String)> = cpe_entries
        .iter()
        .map(|entry| (entry.cpe.name.clone(), entry.source.to_string()))
        .collect();

    validate_symbols(&mut symbols, &package_hints);

    // Stage 5: persist symbols
    emit(
        events,
        ScanStage::Persisting,
        format!("Persisting {} symbols to database...", symbols.len()),
    );

    for symbol in &symbols {
        db::symbol_tables::insert_symbol(pool, symbol)
            .await
            .map_err(|e| PipelineError::Stage {
                stage: "persisting",
                source: e.into(),
            })?;
    }

    // Stage 6: EPSS fetch
    let cve_id_refs: Vec<&str> = cve_ids.iter().map(|s| s.as_str()).collect();
    if !cve_id_refs.is_empty() {
        emit(
            events,
            ScanStage::EpssFetch,
            format!("Fetching EPSS scores for {} CVEs...", cve_id_refs.len()),
        );
        info!("Fetching EPSS scores for {} CVEs...", cve_id_refs.len());

        let epss_entries = client.request_epss_batch(&cve_id_refs).await;
        let epss_scores: Vec<(String, Decimal, Decimal)> = epss_entries
            .into_iter()
            .filter_map(|e| {
                let score = Decimal::try_from(e.epss).ok()?;
                let percentile = Decimal::try_from(e.percentile).ok()?;
                Some((e.cve, score, percentile))
            })
            .collect();

        let updated = db::cve_tables::update_epss_scores(pool, &epss_scores)
            .await
            .map_err(|e| PipelineError::Stage {
                stage: "epss_fetch",
                source: e.into(),
            })?;
        info!("Updated EPSS scores for {updated} CVEs");
    }

    // Stage 7: Rank computation
    emit(
        events,
        ScanStage::Ranking,
        "Computing vulnerability rankings...",
    );
    info!("Computing vulnerability rankings...");

    let flags_updated = db::findings_table::update_symbol_flags(pool, &scan.id)
        .await
        .map_err(|e| PipelineError::Stage {
            stage: "ranking",
            source: e.into(),
        })?;
    let ranks_updated = db::findings_table::compute_rank_scores(pool, &scan.id)
        .await
        .map_err(|e| PipelineError::Stage {
            stage: "ranking",
            source: e.into(),
        })?;
    info!("Updated {flags_updated} symbol flags, computed {ranks_updated} rank scores");

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
            let installed = Cpe::from_cpe_string(cpe_string);
            let associations: Vec<(Uuid, String)> = cves
                .iter()
                .filter(|cve| match installed.version.as_deref() {
                    Some(ver) => cve.affects_version(&installed.vendor, &installed.product, ver),
                    None => true,
                })
                .map(|c| (*cpe_uuid, c.id.clone()))
                .collect();

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
    extractor.validate();
    extractor.infer_languages(&cves);
    extractor.symbols
}

fn validate_symbols(symbols: &mut [Symbol], package_hints: &[(String, String)]) {
    let index = SymbolIndex::build(package_hints);
    info!("Found {} symbols", index.entries.len());
    if !index.is_available() {
        info!("Symbol validation skipped (not running on Linux)");
        return;
    }
    for symbol in symbols.iter_mut() {
        if let Some(resolved) = index.resolve(&symbol.name)
            && let Some(first) = resolved.first()
        {
            symbol.binary_path = Some(first.binary_path.to_string_lossy().into());
            symbol.probe_type = Some(first.probe_type.to_string());
            symbol.validated = true;
        }
    }
    let (valid, total) = (
        symbols.iter().filter(|s| s.validated).count(),
        symbols.len(),
    );
    info!("Symbol validation: {valid}/{total} symbols confirmed on system.");
}
