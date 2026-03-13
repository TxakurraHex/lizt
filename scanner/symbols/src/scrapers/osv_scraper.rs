use crate::scrapers::description_scraper::scrape_description;
use crate::scrapers::git_scraper::scrape_diff;
use crate::symbol_extractor::Scraper;
use async_trait::async_trait;
use common::cve::Cve;
use common::symbol::Symbol;
use rest::rest_client::LiztRestClient;
use std::sync::Arc;

pub struct OsvScraper {
    client: Arc<LiztRestClient>,
}

impl OsvScraper {
    pub fn new(client: Arc<LiztRestClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl Scraper for OsvScraper {
    fn name(&self) -> &str {
        "osv"
    }

    async fn scrape(&self, cve: &Cve) -> Vec<Symbol> {
        let Some(osv) = self.client.request_osv(cve.id.as_ref()).await else {
            return vec![];
        };

        let mut symbols = vec![];

        if let Some(details) = osv.details {
            symbols.extend(scrape_description(&details, &cve.id));
        }

        let diffs = futures::future::join_all(osv.patch_urls.iter().map(|url| async {
            self.client.request_patch(url).await.map(|diff| (diff, url.clone()))
        }))
        .await;

        for (diff, url) in diffs.into_iter().flatten() {
            symbols.extend(scrape_diff(diff, &url, &cve.id));
        }

        symbols
    }
}
