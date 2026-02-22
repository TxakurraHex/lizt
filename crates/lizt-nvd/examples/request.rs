use lizt_nvd::rest::NvdRestClient;
use lizt_nvd::nvd_cve::NvdCve;
fn main() {
    let api_key = std::env::var("API_KEY").ok();
    let nvd_client = NvdRestClient::new(api_key);
    let match_string = String::from("cpe:2.3:a:openssl:openssl:3.0.19");
    if let Some(cpe_match) = cpe_match(&nvd_client, &match_string) {
        println!("CpeMatch: {:?}", cpe_match);
        if let Some(cves) = cve_results(&nvd_client, &cpe_match) {
           for cve in &cves {
               println!("CVE: {:?}", cve);
           }
            println!("Found {} CVEs", cves.len());
        }
    }
}

fn cpe_match(client: &NvdRestClient, cpe_match: &String) -> Option<String> {
    match client.request_cpe_data(cpe_match) {
        Some(cpe_data) => {
            for product in cpe_data {
                if product.cpe.deprecated == false {
                    return Some(product.cpe.cpe_name)
                }
            }
        },
        None => {
            eprintln!("No match");
        }
    }
    None
}

fn cve_results(client: &NvdRestClient, cpe_name: &String) -> Option<Vec<NvdCve>> {
    match client.request_cve_data(cpe_name) {
        Some(cve_data) => {
            let cves = cve_data.into_iter().map(|cve| cve.cve).collect();
            return Some(cves)
        }
        None => {
            eprintln!("No CVEs resulting from {}", cpe_name);
        }
    }
    None
}