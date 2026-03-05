use lizt_core::cpe::Cpe;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct NvdCpeResponse {
    pub products: Option<Vec<NvdProduct>>,
}

#[derive(Debug, Deserialize)]
pub struct NvdProduct {
    pub cpe: NvdCpeItem,
}

#[derive(Debug, Deserialize)]
pub struct NvdCpeItem {
    #[serde(rename = "cpeName")]
    pub cpe_name: String,
    #[serde(rename = "cpeNameId")]
    pub cpe_name_id: String,
    pub titles: Option<Vec<NvdCpeTitle>>,
}

#[derive(Debug, Deserialize)]
pub struct NvdCpeTitle {
    pub title: String,
    pub lang: String,
}

impl From<NvdCpeItem> for Cpe {
    fn from(item: NvdCpeItem) -> Self {
        Cpe::from_cpe_string(&item.cpe_name)
    }
}
