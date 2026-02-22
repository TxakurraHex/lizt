use serde::Deserialize;
use lizt_core::cve::Cve;

#[derive(Debug, Deserialize)]
pub struct NvdCveResponse {
    pub vulnerabilities: Option<Vec<NvdVulnerability>>,
}

#[derive(Debug, Deserialize)]
pub struct NvdVulnerability {
    pub cve: Cve,
}

#[derive(Debug, Deserialize)]
pub struct GitHubIssue {
    pub title: Option<String>,
    pub body: Option<String>,
}
