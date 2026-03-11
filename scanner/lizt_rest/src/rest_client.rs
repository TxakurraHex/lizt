const MAX_GITHUB_RETRIES: u32 = 3;
const NVD_CVE_ENDPOINT: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_CPE_ENDPOINT: &str = "https://services.nvd.nist.gov/rest/json/cpes/2.0";

use crate::nvd::cpe_response::{NvdCpeResponse, NvdProduct};
use crate::nvd::cve_response::{NvdCveResponse, NvdVulnerability};
use crate::nvd::github_response::GitHubIssue;
use crate::rate_limiter::RateLimiter;
use log::{debug, error};
use reqwest::Client;
use std::time::Duration;

pub struct LiztRestClient {
    client: Client,
    nvd_limiter: RateLimiter,
    github_limiter: RateLimiter,
    nvd_key: Option<String>,
    github_token: Option<String>,
}

impl LiztRestClient {
    pub fn new(nvd_api_key: Option<String>, github_token: Option<String>) -> Self {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::USER_AGENT,
            "NVD-CPE-Retriever/1.0".parse().unwrap(),
        );

        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client");

        Self {
            client,
            nvd_key: nvd_api_key.clone(),
            github_token: github_token.clone(),
            nvd_limiter: RateLimiter::nvd(nvd_api_key.is_some()),
            github_limiter: RateLimiter::github(github_token.is_some()),
        }
    }

    pub async fn request_cpe_data(&self, cpe_match: &str) -> Option<Vec<NvdProduct>> {
        loop {
            self.nvd_limiter.acquire().await;
            let mut request = self
                .client
                .get(NVD_CPE_ENDPOINT)
                .query(&[("cpeMatchString", cpe_match)]);
            if let Some(nvd_key) = &self.nvd_key {
                request = request.header("apiKey", nvd_key);
            }
            debug!("Sending request {:?}", request);
            match request.send().await {
                Ok(resp)
                    if resp.status() == reqwest::StatusCode::FORBIDDEN
                        || resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS =>
                {
                    self.nvd_limiter.release();
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
                Ok(resp) if resp.status().is_success() => {
                    let text = resp.text().await.ok()?;
                    return match serde_json::from_str::<NvdCpeResponse>(&text) {
                        Ok(data) => data
                            .products
                            .and_then(|v| if v.is_empty() { None } else { Some(v) }),
                        Err(e) => {
                            error!("Error parsing CPE {}: {}", cpe_match, e);
                            None
                        }
                    };
                }
                Ok(resp) => {
                    error!(
                        "Failed to fetch CPE match for {}: {}",
                        cpe_match,
                        resp.status()
                    );
                    return None;
                }
                Err(e) => {
                    self.nvd_limiter.release();
                    error!("Error fetching CPE {}: {}", cpe_match, e);
                    return None;
                }
            }
        }
    }

    pub async fn request_cve_data(&self, cpe_name: &str) -> Option<Vec<NvdVulnerability>> {
        loop {
            self.nvd_limiter.acquire().await;
            let mut request = self
                .client
                .get(NVD_CVE_ENDPOINT)
                .query(&[("cpeName", cpe_name)]);
            if let Some(nvd_key) = &self.nvd_key {
                request = request.header("apiKey", nvd_key);
            }
            debug!("Sending request {:?}", request);
            match request.send().await {
                Ok(resp)
                    if resp.status() == reqwest::StatusCode::FORBIDDEN
                        || resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS =>
                {
                    self.nvd_limiter.release();
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
                Ok(resp) if resp.status().is_success() => {
                    return match resp.json::<NvdCveResponse>().await {
                        Ok(data) => data
                            .vulnerabilities
                            .and_then(|v| if v.is_empty() { None } else { Some(v) }),
                        Err(e) => {
                            error!("Error parsing CVE from cpeName {}: {}", cpe_name, e);
                            None
                        }
                    };
                }
                Ok(resp) => {
                    error!(
                        "Error fetching CVEs for CPE string {}: {}",
                        cpe_name,
                        resp.status()
                    );
                    return None;
                }
                Err(e) => {
                    self.nvd_limiter.release();
                    error!("Error fetching CVE from cpeName {}: {}", cpe_name, e);
                    return None;
                }
            }
        }
    }

    pub async fn request_cve_by_id(&self, cve_id: &str) -> Option<Vec<NvdVulnerability>> {
        loop {
            self.nvd_limiter.acquire().await;
            let mut request = self
                .client
                .get(NVD_CVE_ENDPOINT)
                .query(&[("cveId", cve_id)]);
            if let Some(nvd_key) = &self.nvd_key {
                request = request.header("apiKey", nvd_key);
            }
            debug!("Sending request {:?}", request);
            match request.send().await {
                Ok(resp)
                    if resp.status() == reqwest::StatusCode::FORBIDDEN
                        || resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS =>
                {
                    self.nvd_limiter.release();
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
                Ok(resp) if resp.status().is_success() => {
                    return match resp.json::<NvdCveResponse>().await {
                        Ok(data) => data
                            .vulnerabilities
                            .and_then(|v| if v.is_empty() { None } else { Some(v) }),
                        Err(e) => {
                            error!("Error parsing CVE {}: {}", cve_id, e);
                            None
                        }
                    };
                }
                Ok(resp) => {
                    error!(
                        "Error fetching CVE from cveId {}: {}",
                        cve_id,
                        resp.status()
                    );
                    return None;
                }
                Err(e) => {
                    self.nvd_limiter.release();
                    error!("Error fetching CVE {}: {}", cve_id, e);
                    return None;
                }
            }
        }
    }

    pub async fn request_patch(&self, commit_url: &str) -> Option<String> {
        let patch_url = to_patch_url(commit_url)?;
        let mut retries = 0;
        loop {
            if retries >= MAX_GITHUB_RETRIES {
                error!("Max retries reached for commit diff {}", commit_url);
                return None;
            }
            self.github_limiter.acquire().await;
            let mut request = self.client.get(&patch_url);
            if let Some(github_key) = &self.github_token {
                request = request.header("Authorization", format!("Bearer {}", github_key));
            }
            debug!("Sending request {:?}", request);
            match request.send().await {
                Ok(resp)
                    if resp.status() == reqwest::StatusCode::FORBIDDEN
                        || resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS =>
                {
                    self.github_limiter.release();
                    retries += 1;
                    tokio::time::sleep(github_wait_until_reset(&resp)).await;
                }
                Ok(resp) if resp.status().is_success() => return resp.text().await.ok(),
                Ok(resp) => {
                    error!(
                        "Couldn't get commit diff from {} (status {})",
                        commit_url,
                        resp.status()
                    );
                    return None;
                }
                Err(e) => {
                    self.github_limiter.release();
                    error!("Couldn't get commit diff from {}: {}", commit_url, e);
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
        let mut retries = 0;
        loop {
            if retries >= MAX_GITHUB_RETRIES {
                error!("Max retries reached for GitHub issue {}", issue_url);
                return None;
            }
            self.github_limiter.acquire().await;
            let mut request = self.client.get(&api_url);
            if let Some(github_key) = &self.github_token {
                request = request.header("Authorization", format!("Bearer {}", github_key));
            }
            debug!("Sending request {:?}", request);
            match request.send().await {
                Ok(resp)
                    if resp.status() == reqwest::StatusCode::FORBIDDEN
                        || resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS =>
                {
                    self.github_limiter.release();
                    retries += 1;
                    tokio::time::sleep(github_wait_until_reset(&resp)).await;
                }
                Ok(resp) if resp.status().is_success() => {
                    return match resp.json::<GitHubIssue>().await {
                        Ok(data) => Some(data),
                        Err(e) => {
                            error!("Couldn't parse GitHub issue from {}: {}", api_url, e);
                            None
                        }
                    };
                }
                Ok(resp) => {
                    error!(
                        "Couldn't get GitHub issue from {}: {}",
                        api_url,
                        resp.status()
                    );
                    return None;
                }
                Err(e) => {
                    self.github_limiter.release();
                    error!("Couldn't get GitHub issue from {}: {}", api_url, e);
                    return None;
                }
            }
        }
    }
}

fn to_patch_url(url: &str) -> Option<String> {
    if url.contains("github.com") || url.contains("gitlab.com") {
        Some(format!("{}.patch", url.trim_end_matches('/')))
    } else if url.contains("git.kernel.org") {
        // kernel.org uses a PoW rate-limiter, not dealing with that (yet...) just use GitHub mirror
        let hash = url
            .split('?')
            .nth(1)
            .and_then(|qs| qs.split('&').find(|p| p.starts_with("id=")))
            .map(|p| &p[3..])?;
        Some(format!(
            "https://github.com/torvalds/linux/commit/{hash}.patch"
        ))
    } else {
        None
    }
}

fn github_wait_until_reset(resp: &reqwest::Response) -> Duration {
    let reset_unix: u64 = resp
        .headers()
        .get("X-RateLimit-Reset")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let secs_to_wait = reset_unix.saturating_sub(now) + 1;
    Duration::from_secs(secs_to_wait)
}
