use reqwest::blocking::Client;
use crate::nvd_cpe::{NvdCpeResp, NvdProduct};
use crate::nvd_cve::{NvdVulnerability, NvdCveResponse};

pub struct NvdRestClient {
    client: Client,
}

impl NvdRestClient {
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
}