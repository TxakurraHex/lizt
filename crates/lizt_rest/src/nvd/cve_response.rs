use chrono::{DateTime, Utc};
use lizt_core::cve::{CpeMatch, Cve, CvssInfo};
use lizt_core::inventory_item::CpeEntry;
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
    pub base_score: f64,
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

impl TryFrom<NvdCveItem> for Cve {
    type Error = chrono::ParseError;

    fn try_from(value: NvdCveItem) -> Result<Self, Self::Error> {
        Ok(Cve {
            id: value.id,
            descriptions: value
                .descriptions
                .and_then(|ds| ds.into_iter().find(|d| d.lang == "en"))
                .map(|d| d.value),
            published: Some(DateTime::parse_from_rfc3339(&value.published)?.with_timezone(&Utc)),
            references: value
                .references
                .map(|refs| refs.into_iter().map(|r| r.url).collect()),
            cvss: value.metrics.and_then(|m| m.best_cvss()),
            cpes: value.configurations.map(|configs| {
                configs
                    .into_iter()
                    .flat_map(|c| c.nodes)
                    .flat_map(|n| n.cpe_match)
                    .map(|m| CpeMatch {
                        cpe_entry: CpeEntry::from_cpe_string(m.criteria.as_str()),
                        vulnerable: m.vulnerable,
                        version_start_including: m.version_start_including,
                        version_start_excluding: m.version_start_excluding,
                        version_end_including: m.version_end_including,
                        version_end_excluding: m.version_end_excluding,
                    })
                    .collect()
            }),
        })
    }
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
