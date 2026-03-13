use crate::rest_client::LiztRestClient;
use common::cpe::{Cpe, CpeEntry};
use std::sync::Arc;

pub struct CpeResolver {
    client: Arc<LiztRestClient>,
}

impl CpeResolver {
    pub fn new(client: Arc<LiztRestClient>) -> Self {
        Self { client }
    }

    pub async fn resolve(&self, item: &CpeEntry) -> Vec<CpeEntry> {
        self.client
            .request_cpe_data(&item.cpe.to_cpe_string())
            .await
            .into_iter()
            .flatten()
            .map(|product| CpeEntry {
                cpe: Cpe::from(product.cpe),
                source: item.source.clone(),
                cpe_confidence: item.cpe_confidence.clone(),
            })
            .collect()
    }

    pub async fn resolve_all(&self, items: &[CpeEntry]) -> Vec<CpeEntry> {
        futures::future::join_all(items.iter().map(|item| self.resolve(item)))
            .await
            .into_iter()
            .flatten()
            .collect()
    }
}
