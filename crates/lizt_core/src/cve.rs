use serde::Deserialize;

#[derive(Debug, Deserialize, Eq, PartialEq, Clone, Hash)]
pub struct Cve {
    pub id: String,
    pub descriptions: Option<Vec<CveDescription>>,
    pub published: Option<String>,
    pub references: Option<Vec<CveReference>>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Clone, Hash)]
pub struct CveDescription {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Clone, Hash)]
pub struct CveReference {
    pub url: String,
}