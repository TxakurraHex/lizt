use crate::nvd::cpe_response::NvdProduct;
use crate::rest_client::LiztRestClient;
use lizt_core::inventory_item::InventoryItem;
use std::sync::Arc;

pub struct CpeResolver {
    client: Arc<LiztRestClient>,
}

impl CpeResolver {
    pub fn new(client: Arc<LiztRestClient>) -> Self {
        Self { client }
    }

    pub async fn resolve(&self, item: &InventoryItem) -> Vec<NvdProduct> {
        self.client
            .request_cpe_data(&item.cpe.to_cpe_string())
            .await
            .unwrap_or_default()
    }

    pub async fn resolve_all(&self, items: &[InventoryItem]) -> Vec<NvdProduct> {
        futures::future::join_all(items.iter().map(|item| self.resolve(item)))
            .await
            .into_iter()
            .flatten()
            .collect()
    }
}
