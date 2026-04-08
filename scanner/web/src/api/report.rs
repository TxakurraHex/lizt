use super::state::AppState;
use axum::{
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::IntoResponse,
};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct ReportParams {
    #[serde(default = "default_format")]
    pub format: String,
}

fn default_format() -> String {
    "json".to_string()
}

pub async fn download(
    State(state): State<AppState>,
    Query(params): Query<ReportParams>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let findings = db::findings_table::get_all_finding_summaries(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (bytes, content_type, filename) = match params.format.as_str() {
        "csv" => {
            let data = common::report::to_csv(&findings)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            (data, "text/csv", "lizt-report.csv")
        }
        _ => {
            let data = common::report::to_json(&findings)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            (data, "application/json", "lizt-report.json")
        }
    };

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")).unwrap(),
    );

    Ok((headers, bytes))
}
