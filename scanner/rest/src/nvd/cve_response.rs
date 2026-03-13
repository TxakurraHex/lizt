use chrono::{DateTime, Utc};
use common::cpe::Cpe;
use common::cve::{Cve, CveCpe, CveRef};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct NvdCveResponse {
    pub vulnerabilities: Option<Vec<NvdVulnerability>>,
}

#[derive(Debug, Deserialize)]
pub struct NvdVulnerability {
    pub cve: NvdCveItem,
}

#[derive(Debug, Deserialize)]
pub struct NvdCveItem {
    pub id: String,
    pub descriptions: Option<Vec<NvdCveDescription>>,
    pub published: String,
    #[serde(rename = "lastModified")]
    pub last_modified: String,
    pub references: Option<Vec<NvdCveReference>>,
    pub metrics: Option<NvdMetrics>,
    pub configurations: Option<Vec<NvdConfiguration>>,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq, Clone, Hash)]
pub struct NvdCveReference {
    pub url: String,
    pub source: Option<String>,
    pub tags: Option<Vec<String>>,
}

impl From<NvdCveReference> for CveRef {
    fn from(value: NvdCveReference) -> Self {
        Self {
            url: value.url,
            tags: value.tags,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct NvdCveDescription {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct NvdMetrics {
    #[serde(rename = "cvssMetricV2", default)]
    pub v2: Vec<NvdCvssEntry>,
    #[serde(rename = "cvssMetricV31", default)]
    pub v31: Vec<NvdCvssEntry>,
    #[serde(rename = "cvssMetricV40", default)]
    pub v40: Vec<NvdCvssEntry>,
}

// All three versions share these fields despite different shapes
#[derive(Debug, Deserialize)]
pub struct NvdCvssEntry {
    pub source: String,
    #[serde(rename = "type")]
    pub entry_type: String, // "Primary" or "Secondary"
    #[serde(rename = "cvssData")]
    pub cvss_data: NvdCvssData,
}

#[derive(Debug, Deserialize)]
pub struct NvdCvssData {
    pub version: String,
    #[serde(rename = "baseScore")]
    pub base_score: Decimal,
    #[serde(rename = "vectorString")]
    pub vector_string: String,
}

#[derive(Debug, Deserialize)]
pub struct NvdConfiguration {
    pub nodes: Vec<NvdNode>,
}

#[derive(Debug, Deserialize)]
pub struct NvdNode {
    pub operator: Option<String>,
    #[serde(rename = "cpeMatch", default)]
    pub cpe_match: Vec<NvdCpeMatch>,
}

#[derive(Debug, Deserialize)]
pub struct NvdCpeMatch {
    pub vulnerable: bool,
    pub criteria: String,
    #[serde(rename = "versionStartIncluding")]
    pub version_start_including: Option<String>,
    #[serde(rename = "versionStartExcluding")]
    pub version_start_excluding: Option<String>,
    #[serde(rename = "versionEndIncluding")]
    pub version_end_including: Option<String>,
    #[serde(rename = "versionEndExcluding")]
    pub version_end_excluding: Option<String>,
}

impl From<NvdCveItem> for Cve {
    fn from(value: NvdCveItem) -> Self {
        let cvss = value.metrics.and_then(|m| m.best_cvss());
        Cve {
            id: value.id,
            descriptions: value
                .descriptions
                .and_then(|ds| ds.into_iter().find(|d| d.lang == "en"))
                .map(|d| d.value),
            published: DateTime::parse_from_rfc3339(&value.published)
                .ok()
                .map(|dt| dt.with_timezone(&Utc)),
            refs: value
                .references
                .map(|refs| refs.into_iter().map(CveRef::from).collect()),
            cvss_score: cvss.as_ref().map(|c| c.score),
            cvss_vector: cvss.as_ref().map(|c| c.vector.clone()),
            cvss_version: cvss.as_ref().map(|c| c.version.clone()),
            cpes: value.configurations.map(|configs| {
                configs
                    .into_iter()
                    .flat_map(|c| c.nodes)
                    .flat_map(|n| n.cpe_match)
                    .map(CveCpe::from)
                    .collect()
            }),
        }
    }
}

impl From<NvdCpeMatch> for CveCpe {
    fn from(value: NvdCpeMatch) -> Self {
        CveCpe {
            cpe: Cpe::from_cpe_string(value.criteria.as_str()),
            vulnerable: value.vulnerable,
            version_start_including: value.version_start_including,
            version_start_excluding: value.version_start_excluding,
            version_end_including: value.version_end_including,
            version_end_excluding: value.version_end_excluding,
        }
    }
}

pub struct CvssInfo {
    pub score: Decimal,
    pub vector: String,
    pub version: String,
}

impl NvdMetrics {
    pub fn best_cvss(&self) -> Option<CvssInfo> {
        let entries = [&self.v40, &self.v31, &self.v2];
        entries
            .iter()
            .find_map(|version_entries| version_entries.first())
            .map(|e| CvssInfo {
                score: e.cvss_data.base_score,
                vector: e.cvss_data.vector_string.clone(),
                version: e.cvss_data.version.clone(),
            })
    }
}
