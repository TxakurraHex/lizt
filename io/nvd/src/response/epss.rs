use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct EpssResponse {
    pub data: Vec<EpssEntry>,
}

#[derive(Debug, Deserialize)]
pub struct EpssEntry {
    pub cve: String,
    pub epss: f64,
    pub percentile: f64,
}
