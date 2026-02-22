use serde::Deserialize;


#[derive(Deserialize)]
pub struct NvdCpeResp {
    pub products: Option<Vec<NvdProduct>>,
}

#[derive(Deserialize, Debug)]
pub struct NvdProduct {
    pub cpe: NvdCpe,
}

#[derive(Deserialize, Debug)]
pub struct NvdCpe {
    #[serde(rename = "cpeName")]
    pub cpe_name: String,
    #[serde(rename = "cpeNameId")]
    pub cpe_name_id: String,
    pub created: String,
    pub deprecated: bool,
    #[serde(rename = "deprecatedBy")]
    pub deprecated_by: Option<Vec<NvdCpeDep>>,
}

#[derive(Deserialize, Debug)]
pub struct NvdCpeDep {
    #[serde(rename = "cpeName")]
    pub cpe_name: String,
    #[serde(rename = "cpeNameId")]
    pub cpe_name_id: String,
}
