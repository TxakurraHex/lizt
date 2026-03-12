use lizt_rest::nvd::cpe_response::NvdCpeItem;
use lizt_rest::nvd::cve_response::NvdCveItem;
use lizt_rest::rest_client::LiztRestClient;
use log::{error, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let api_key = std::env::var("NVD_API_KEY").ok();
    let github_token = std::env::var("GITHUB_TOKEN").ok();
    let rest_client = LiztRestClient::new(api_key, github_token);
    let match_string = String::from("cpe:2.3:a:openssl:openssl:3.0.19");
    if let Some(cpe_matches) = cpe_match(&rest_client, &match_string).await {
        for product in cpe_matches {
            if let Some(cves) = cve_results(&rest_client, &product.cpe_name).await {
                for cve in &cves {
                    info!("CVE: {:?}", cve);
                    if let Some(ovd_extr) = rest_client.request_osv(&cve.id).await {
                        info!("OVD responses: {:?}", ovd_extr);
                    } else {
                        error!("No OVD responses");
                    }
                }
                info!("Found {} CVEs", cves.len());
            }
        }
    }

    Ok(())
}

async fn cpe_match(client: &LiztRestClient, cpe_match: &str) -> Option<Vec<NvdCpeItem>> {
    Some(
        client
            .request_cpe_data(cpe_match)
            .await?
            .into_iter()
            .map(|f| f.cpe)
            .collect(),
    )
}

async fn cve_results(client: &LiztRestClient, cpe_name: &str) -> Option<Vec<NvdCveItem>> {
    Some(
        client
            .request_cve_data(cpe_name)
            .await?
            .into_iter()
            .map(|f| f.cve)
            .collect(),
    )
}
