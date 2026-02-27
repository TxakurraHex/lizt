use crate::nvd::cpe_response::{NvdCpeResponse, NvdProduct};
use crate::nvd::cve_response::{NvdCveResponse, NvdVulnerability};
use crate::nvd::github_response::GitHubIssue;
use crate::rate_limiter::RateLimiter;
use reqwest::Client;
use std::time::Duration;

pub struct LiztRestClient {
    client: Client,
    limiter: RateLimiter,
}

impl LiztRestClient {
    pub fn new(api_key: Option<String>) -> Self {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::USER_AGENT,
            "NVD-CPE-Retriever/1.0".parse().unwrap(),
        );
        if let Some(key) = &api_key {
            headers.insert("apiKey", key.parse().unwrap());
        }

        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client");

        Self {
            client,
            limiter: RateLimiter::new(api_key.is_some()),
        }
    }

    pub async fn request_cpe_data(&self, cpe_match: &str) -> Option<Vec<NvdProduct>> {
        let url = format!(
            "https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString={}",
            cpe_match
        );
        loop {
            self.limiter.acquire().await;
            match self.client.get(&url).send().await {
                Ok(resp) if resp.status() == reqwest::StatusCode::FORBIDDEN => {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
                Ok(resp) => {
                    let text = resp.text().await.ok()?;
                    return match serde_json::from_str::<NvdCpeResponse>(&text) {
                        Ok(data) => data
                            .products
                            .and_then(|v| if v.is_empty() { None } else { Some(v) }),
                        Err(e) => {
                            eprintln!("Error parsing CPE {}: {}", cpe_match, e);
                            None
                        }
                    };
                }
                Err(e) => {
                    eprintln!("Error fetching CPE {}: {}", cpe_match, e);
                    return None;
                }
            }
        }
    }

    pub async fn request_cve_data(&self, cpe_name: &str) -> Option<Vec<NvdVulnerability>> {
        let url = format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={}",
            cpe_name
        );
        loop {
            self.limiter.acquire().await;
            match self.client.get(&url).send().await {
                Ok(resp) if resp.status() == reqwest::StatusCode::FORBIDDEN => {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
                Ok(resp) => {
                    return match resp.json::<NvdCveResponse>().await {
                        Ok(data) => data
                            .vulnerabilities
                            .and_then(|v| if v.is_empty() { None } else { Some(v) }),
                        Err(e) => {
                            eprintln!("Error parsing CVE from cpeName {}: {}", cpe_name, e);
                            None
                        }
                    };
                }
                Err(e) => {
                    eprintln!("Error fetching CVE from cpeName {}: {}", cpe_name, e);
                    return None;
                }
            }
        }
    }

    pub async fn request_cve_by_id(&self, cve_id: &str) -> Option<Vec<NvdVulnerability>> {
        let url = format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}",
            cve_id
        );
        loop {
            self.limiter.acquire().await;
            match self.client.get(&url).send().await {
                Ok(resp) if resp.status() == reqwest::StatusCode::FORBIDDEN => {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
                Ok(resp) => {
                    return match resp.json::<NvdCveResponse>().await {
                        Ok(data) => data
                            .vulnerabilities
                            .and_then(|v| if v.is_empty() { None } else { Some(v) }),
                        Err(e) => {
                            eprintln!("Error parsing CVE {}: {}", cve_id, e);
                            None
                        }
                    };
                }
                Err(e) => {
                    eprintln!("Error fetching CVE {}: {}", cve_id, e);
                    return None;
                }
            }
        }
    }

    pub async fn request_github_commit_diff(&self, commit_url: &str) -> Option<String> {
        if !commit_url.contains("github.com") {
            return None;
        }
        let patch_url = format!("{}.patch", commit_url.trim_end_matches('/'));
        loop {
            self.limiter.acquire().await;
            match self.client.get(&patch_url).send().await {
                Ok(resp) if resp.status() == reqwest::StatusCode::FORBIDDEN => {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
                Ok(resp) if resp.status().is_success() => return resp.text().await.ok(),
                Ok(resp) => {
                    eprintln!(
                        "Couldn't get commit diff from {} (status {})",
                        commit_url,
                        resp.status()
                    );
                    return None;
                }
                Err(e) => {
                    eprintln!("Couldn't get commit diff from {}: {}", commit_url, e);
                    return None;
                }
            }
        }
    }

    pub async fn request_github_issue(&self, issue_url: &str) -> Option<GitHubIssue> {
        if !issue_url.contains("github.com") {
            return None;
        }
        let api_url = issue_url
            .replace("github.com", "api.github.com/repos")
            .replace("/pull/", "/pulls/");
        loop {
            self.limiter.acquire().await;
            match self.client.get(&api_url).send().await {
                Ok(resp) if resp.status() == reqwest::StatusCode::FORBIDDEN => {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
                Ok(resp) => {
                    return match resp.json::<GitHubIssue>().await {
                        Ok(data) => Some(data),
                        Err(e) => {
                            eprintln!("Couldn't parse GitHub issue from {}: {}", api_url, e);
                            None
                        }
                    };
                }
                Err(e) => {
                    eprintln!("Couldn't get GitHub issue from {}: {}", api_url, e);
                    return None;
                }
            }
        }
    }
}
