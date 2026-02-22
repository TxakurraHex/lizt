use reqwest::blocking::Client;
use crate::nvd_cpe::{NvdCpeResp, NvdProduct};
use crate::nvd_cve::{NvdVulnerability, NvdCveResponse, GitHubIssue};

pub struct LiztRestClient {
    client: Client,
}

impl LiztRestClient {
    pub fn new (api_key: Option<String>) -> Self {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::USER_AGENT,
            "NVD-CPE-Retreiver/1.0".parse().unwrap(),
        );
        if let Some(key) = api_key {
            headers.insert("apiKey", key.parse().unwrap());
        }

        let client= Client::builder()
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client to request CPE strings");

        Self { client }
    }

    pub fn request_cpe_data(&self, cpe_match: &String) -> Option<Vec<NvdProduct>> {
        let url = format!("https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString={}", cpe_match);

        match self.client.get(&url).send() {
            Ok(resp) => match resp.json::<NvdCpeResp>() {
                Ok(data) => data
                    .products
                    .and_then(|v| if v.is_empty() { None } else { Some(v) }),
                Err(e) => {
                    eprintln!("Error parsing CPE {}: {}", cpe_match, e);
                    None
                }
            },
            Err(e) => {
                eprintln!("Error fetching CPE {}: {}", cpe_match, e);
                None
            }
        }
    }

    pub fn request_cve_data(&self, cpe_name: &String) -> Option<Vec<NvdVulnerability>> {
        let url = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={}", cpe_name);

        match self.client.get(&url).send() {
            Ok(resp) => match resp.json::<NvdCveResponse>() {
                Ok(data) => data
                    .vulnerabilities
                    .and_then(|v| if v.is_empty() { None } else { Some(v) }),
                Err(e) => {
                    eprintln!("Error parsing CVE from cpeName {}: {}", cpe_name, e);
                    None
                }
            },
            Err(e) => {
                eprintln!("Error fetching CVE from cpeName {}: {}",cpe_name, e);
                None
            }
        }
    }

    pub fn request_github_commit_diff(&self, commit_url: &String) -> Option<String> {
        if !commit_url.contains("github.com") {
            return None;
        }

        let patch_url = format!("{}.patch", commit_url.trim_end_matches("/"));
        match self.client.get(&patch_url).send() {
            Ok(resp) if resp.status().is_success() => resp.text().ok(),
            Ok(resp) => {
                eprintln!("Couldn't get commit diff from {} (status {})", commit_url, resp.status());
                None
            }
            Err(e) => {
                eprintln!("Couldn't get commit diff from {}: {}", commit_url, e);
                None
            }
        }
    }

    pub fn request_github_issue(&self, issue_url: &String) -> Option<GitHubIssue> {
        if !issue_url.contains("github.com") {
            return None;
        }

        let api_url = issue_url
            .replace("github.com", "api.github.com/repos")
            .replace("/pull/", "/pulls/");

        match self.client.get(&api_url).send() {
            Ok(resp) => match resp.json::<GitHubIssue>() {
                Ok(data) => Some(data),
                Err(e) => {
                    eprintln!("Couldn't parse GitHub issue from {}", api_url);
                    None
                }
            }
            Err(e) => {
                eprintln!("Couldn't get GitHub issue from {}: {}", api_url, e);
                None
            }
        }
    }
}