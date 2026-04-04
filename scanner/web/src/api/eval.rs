use super::scan::{StartScanResponse, spawn_stage_tracker};
use super::state::AppState;
use axum::{Json, extract::State, http::StatusCode};
use pipeline::{ScanEvent, run_eval};
use serde::Deserialize;
use tokio::sync::broadcast::error::RecvError;

#[derive(Deserialize)]
pub struct StartEvalRequest {
    pub fixture: String,
}

pub async fn start(
    State(state): State<AppState>,
    Json(body): Json<StartEvalRequest>,
) -> Result<Json<StartScanResponse>, (StatusCode, String)> {
    let mut running = state.scan_running.lock().await;
    if *running {
        return Err((StatusCode::CONFLICT, "A scan is already running".into()));
    }
    *running = true;
    drop(running);

    let mut rx = state.scan_tx.subscribe();
    let pool = state.pool.clone();
    let client = state.client.clone();
    let tx = state.scan_tx.clone();
    let running = state.scan_running.clone();
    let fixture = body.fixture;

    tokio::spawn(async move {
        let result = run_eval(&pool, client, &fixture, tx).await;
        *running.lock().await = false;
        result
    });

    let scan_id = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            match rx.recv().await {
                Ok(ScanEvent::Started { scan_id }) => return Ok(scan_id),
                Ok(_) => continue,
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => {
                    return Err("pipeline exited before emitting Started".to_string());
                }
            }
        }
    })
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Eval start timed out".into(),
        )
    })?
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    spawn_stage_tracker(scan_id, rx, state.scan_stage.clone());

    Ok(Json(StartScanResponse { scan_id }))
}
