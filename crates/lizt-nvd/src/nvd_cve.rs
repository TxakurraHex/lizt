use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct NvdCveResponse {
    pub vulnerabilities: Option<Vec<NvdVulnerability>>,
}

#[derive(Debug, Deserialize)]
pub struct NvdVulnerability {
    pub cve: NvdCve,
}

#[derive(Debug, Deserialize)]
pub struct NvdCve {
    pub descriptions: Option<Vec<NvdDescription>>,
    pub published: Option<String>,
    pub references: Option<Vec<NvdReference>>,
}

#[derive(Debug, Deserialize)]
pub struct NvdDescription {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct NvdReference {
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct GitHubIssue {
    pub title: Option<String>,
    pub body: Option<String>,
}
