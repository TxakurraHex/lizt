const MAX_RETRIES: u32 = 3;
const NVD_CVE_ENDPOINT: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_CPE_ENDPOINT: &str = "https://services.nvd.nist.gov/rest/json/cpes/2.0";
const OSV_ENDPOINT: &str = "https://api.osv.dev/v1/vulns";

use crate::rate_limiter::RateLimiter;
use crate::response::{
    cpe::{NvdCpeResponse, NvdProduct},
    cve::{NvdCveResponse, NvdVulnerability},
    github::GitHubIssue,
    osv::{OsvExtracted, OsvResponse},
};
use log::{debug, error};
use reqwest::Client;
use std::time::Duration;

pub struct LiztClient {
    client: Client,
    nvd_limiter: RateLimiter,
    github_limiter: RateLimiter,
    osv_limiter: RateLimiter,
    nvd_key: Option<String>,
    github_token: Option<String>,
}

impl LiztClient {
    pub fn new(nvd_api_key: Option<String>, github_token: Option<String>) -> Self {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::USER_AGENT, "lizt/1.0".parse().unwrap());

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
            osv_limiter: RateLimiter::osv(),
        }
    }

    pub async fn request_cpe_data(&self, cpe_match: &str) -> Option<Vec<NvdProduct>> {
        self.nvd_limiter.acquire().await;
        for attempt in 0..MAX_RETRIES {
            let mut request = self
                .client
                .get(NVD_CPE_ENDPOINT)
                .query(&[("cpeMatchString", cpe_match)]);
            if let Some(nvd_key) = &self.nvd_key {
                request = request.header("apiKey", nvd_key);
            }
            debug!(
                "Sending request to CPE endpoint with CPE match string {}",
                cpe_match
            );
            match request.send().await {
                Ok(resp)
                    if resp.status() == reqwest::StatusCode::FORBIDDEN
                        || resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS =>
                {
                    if attempt + 1 == MAX_RETRIES {
                        break;
                    }
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
                    error!("Error fetching CPE {}: {}", cpe_match, e);
                    return None;
                }
            }
        }
        error!(
            "Failed to retrieve CPE data for {}, exhausted allotted retries ({})",
            cpe_match, MAX_RETRIES
        );
        None
    }

    pub async fn request_cve_data(&self, cpe_name: &str) -> Option<Vec<NvdVulnerability>> {
        self.nvd_limiter.acquire().await;
        for attempt in 0..MAX_RETRIES {
            let mut request = self
                .client
                .get(NVD_CVE_ENDPOINT)
                .query(&[("cpeName", cpe_name)]);
            if let Some(nvd_key) = &self.nvd_key {
                request = request.header("apiKey", nvd_key);
            }

            debug!("Sending request to CVE endpoint with CPE name {}", cpe_name);
            match request.send().await {
                Ok(resp)
                    if resp.status() == reqwest::StatusCode::FORBIDDEN
                        || resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS =>
                {
                    if attempt + 1 == MAX_RETRIES {
                        break;
                    }
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
                    error!("Error fetching CVE from cpeName {}: {}", cpe_name, e);
                    return None;
                }
            }
        }
        error!(
            "Failed to retrieve CVE data for {}, exhausted allotted retries ({})",
            cpe_name, MAX_RETRIES
        );
        None
    }

    pub async fn request_cve_by_id(&self, cve_id: &str) -> Option<Vec<NvdVulnerability>> {
        self.nvd_limiter.acquire().await;
        for attempt in 0..MAX_RETRIES {
            let mut request = self
                .client
                .get(NVD_CVE_ENDPOINT)
                .query(&[("cveId", cve_id)]);
            if let Some(nvd_key) = &self.nvd_key {
                request = request.header("apiKey", nvd_key);
            }
            debug!("Sending request to CVE endpoint for {}", cve_id);
            match request.send().await {
                Ok(resp)
                    if resp.status() == reqwest::StatusCode::FORBIDDEN
                        || resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS =>
                {
                    if attempt + 1 == MAX_RETRIES {
                        break;
                    }
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
                    error!("Error fetching CVE {}: {}", cve_id, e);
                    return None;
                }
            }
        }
        error!(
            "Failed to retrieve CVE data for {}, exhausted allotted retries ({})",
            cve_id, MAX_RETRIES
        );
        None
    }

    pub async fn request_patch(&self, commit_url: &str) -> Option<String> {
        let patch_url = to_patch_url(commit_url)?;
        self.github_limiter.acquire().await;

        for attempt in 0..MAX_RETRIES {
            let mut request = self.client.get(&patch_url);
            if let Some(github_key) = &self.github_token {
                request = request.header("Authorization", format!("Bearer {}", github_key));
            }
            debug!("Sending request for patch: {}", patch_url);
            match request.send().await {
                Ok(resp)
                    if resp.status() == reqwest::StatusCode::FORBIDDEN
                        || resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS =>
                {
                    if attempt + 1 == MAX_RETRIES {
                        break;
                    }
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
                    error!("Couldn't get commit diff from {}: {}", commit_url, e);
                    return None;
                }
            }
        }
        error!(
            "Failed to retrieve {}, exhausted allotted retries ({})",
            patch_url, MAX_RETRIES
        );
        None
    }

    pub async fn request_github_issue(&self, issue_url: &str) -> Option<GitHubIssue> {
        if !issue_url.contains("github.com") {
            return None;
        }
        self.github_limiter.acquire().await;
        let api_url = issue_url
            .replace("github.com", "api.github.com/repos")
            .replace("/pull/", "/pulls/");

        for attempt in 0..MAX_RETRIES {
            let mut request = self.client.get(&api_url);
            if let Some(github_key) = &self.github_token {
                request = request.header("Authorization", format!("Bearer {}", github_key));
            }
            debug!("Sending request for github issue {}", issue_url);
            match request.send().await {
                Ok(resp)
                    if resp.status() == reqwest::StatusCode::FORBIDDEN
                        || resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS =>
                {
                    if attempt + 1 == MAX_RETRIES {
                        break;
                    }
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
                    error!("Couldn't get GitHub issue from {}: {}", api_url, e);
                    return None;
                }
            }
        }

        error!("Max retries reached for GitHub issue {}", issue_url);
        None
    }

    pub async fn request_osv(&self, cve_id: &str) -> Option<OsvExtracted> {
        self.osv_limiter.acquire().await;
        for attempt in 0..MAX_RETRIES {
            let request_url = format!("{}/{}", OSV_ENDPOINT, cve_id);
            let request = self.client.get(&request_url);
            debug!("Sending request to OSV endpoint for {}", cve_id);
            match request.send().await {
                Ok(resp)
                    if resp.status() == reqwest::StatusCode::FORBIDDEN
                        || resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS =>
                {
                    if attempt + 1 == MAX_RETRIES {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
                Ok(resp) if resp.status().is_success() => {
                    let text = resp.text().await.ok()?;
                    return match serde_json::from_str::<OsvResponse>(&text) {
                        Ok(data) => Some(data.extract()),
                        Err(e) => {
                            error!("Error parsing OSV response for {}: {}", cve_id, e);
                            None
                        }
                    };
                }
                Ok(resp) => {
                    error!(
                        "Failed to get OSV response for {}: {}",
                        cve_id,
                        resp.status()
                    );
                    return None;
                }
                Err(e) => {
                    error!("Error fetching OSV data for {}: {}", cve_id, e);
                    return None;
                }
            }
        }
        error!(
            "Failed to retrieve OSV data for {}, exhausted allotted retries ({})",
            cve_id, MAX_RETRIES
        );
        None
    }
}

fn to_patch_url(url: &str) -> Option<String> {
    let trimmed = url.trim_end_matches('/');

    if url.contains("github.com") || url.contains("gitlab.com") {
        Some(format!("{}.patch", trimmed))
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
    } else if url.contains("gitlab.") {
        // Self-hosted GitLab instances (e.g., gitlab.freedesktop.org, gitlab.gnome.org)
        let clean = trimmed.trim_end_matches(".git");
        Some(format!("{clean}.patch"))
    } else if url.contains("/cgit/") || url.contains("git.savannah.gnu.org") {
        // cgit instances — convert commit URLs with ?id=HASH to patch format
        if url.contains("?id=") || url.contains("&id=") {
            let base = url.split('?').next()?;
            let hash = url
                .split('?')
                .nth(1)
                .and_then(|qs| qs.split('&').find(|p| p.starts_with("id=")))
                .map(|p| &p[3..])?;
            let patch_base = base.trim_end_matches("/commit");
            Some(format!("{patch_base}/patch/?id={hash}"))
        } else {
            None
        }
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
    Duration::from_secs(secs_to_wait.min(60))
}
