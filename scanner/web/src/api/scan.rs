use super::state::AppState;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{
        IntoResponse,
        sse::{Event, KeepAlive, Sse},
    },
};
use chrono::{DateTime, Utc};
use pipeline::{ScanEvent, run_scan};
use serde::Serialize;
use sqlx::types::Uuid;
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

// -- Responses --------------------------------------------------------------------------- //

#[derive(Serialize)]
pub struct StartScanResponse {
    pub scan_id: Uuid,
}

#[derive(Serialize)]
pub struct ScanRecord {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub status: String,
}

impl From<common::scan::Scan> for ScanRecord {
    fn from(s: common::scan::Scan) -> Self {
        ScanRecord {
            id: s.id,
            started_at: s.started_at,
            finished_at: s.finished_at,
            status: s.status,
        }
    }
}

// -- Handlers ---------------------------------------------------------------------------- //

/// POST /api/scan: Start a scan in the background
pub async fn start(
    State(state): State<AppState>,
) -> Result<Json<StartScanResponse>, (StatusCode, String)> {
    let mut running = state.scan_running.lock().await;
    if *running {
        return Err((StatusCode::CONFLICT, "A scan is already running".into()));
    }
    *running = true;
    drop(running);

    // Subscribe before spawning to catch the Started event
    let mut rx = state.scan_tx.subscribe();

    let pool = state.pool.clone();
    let client = state.client.clone();
    let tx = state.scan_tx.clone();
    let running = state.scan_running.clone();

    tokio::spawn(async move {
        let result = run_scan(&pool, client, tx).await;
        *running.lock().await = false;
        result
    });

    let scan_id = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            match rx.recv().await {
                Ok(ScanEvent::Started { scan_id }) => return Ok(scan_id),
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => {
                    return Err("pipeline exited before emitting Started".to_string());
                }
            }
        }
    })
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Scan start timed out".into(),
        )
    })?
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(StartScanResponse { scan_id }))
}

/// GET /api/scan: list all scans
pub async fn list(
    State(state): State<AppState>,
) -> Result<Json<Vec<ScanRecord>>, (StatusCode, String)> {
    let scans = db::scans_table::get_scans(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut records: Vec<ScanRecord> = scans.into_iter().map(ScanRecord::from).collect();
    records.sort_by(|a, b| b.started_at.cmp(&a.started_at));
    Ok(Json(records))
}

/// GET /api/scan/{id}: Single scan by ID
pub async fn get_by_id(
    State(state): State<AppState>,
    Path(scan_id): Path<Uuid>,
) -> Result<Json<ScanRecord>, (StatusCode, String)> {
    let scan = db::scans_table::get_scan(&state.pool, &scan_id)
        .await
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    Ok(Json(ScanRecord::from(scan)))
}

pub async fn events(State(state): State<AppState>) -> impl IntoResponse {
    let rx = state.scan_tx.subscribe();

    let stream = BroadcastStream::new(rx).filter_map(|msg| {
        let event = match msg {
            Ok(ScanEvent::Started { scan_id }) => {
                let data = format!(r#"{{"type":"started","scan_id":"{}"}}"#, scan_id);
                Some(Event::default().data(data))
            }
            Ok(ScanEvent::Stage { stage, detail }) => {
                let data = format!(
                    r#"{{"type":"stage","stage":"{}","detail":"{}"}}"#,
                    stage, detail
                );
                Some(Event::default().data(data))
            }
            Ok(ScanEvent::Complete { scan_id }) => {
                let data = format!(r#"{{"type":"complete","scan_id":"{}"}}"#, scan_id);
                Some(Event::default().data(data))
            }
            Ok(ScanEvent::Failed { scan_id, error }) => {
                let data = format!(
                    r#"{{"type":"failed","scan_id":"{}","error":"{}"}}"#,
                    scan_id, error
                );
                Some(Event::default().data(data))
            }
            Err(_) => None,
        };
        event.map(Ok::<_, std::convert::Infallible>)
    });

    let sse = Sse::new(stream).keep_alive(KeepAlive::default());

    // Tell nginx (and other reverse proxies) not to buffer this response
    (
        [("X-Accel-Buffering", "no"), ("Cache-Control", "no-cache")],
        sse,
    )
}
