use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct OsvResponse {
    pub details: Option<String>,
    pub affected: Vec<OsvAffected>,
    pub references: Option<Vec<OsvReferences>>,
}

#[derive(Debug, Deserialize)]
pub struct OsvAffected {
    pub package: Option<OsvAffectedPackage>,
    pub ranges: Option<Vec<OsvAffectedRange>>,
}

#[derive(Debug, Deserialize)]
pub struct OsvAffectedPackage {
    pub ecosystem: String,
    pub name: String,
    pub purl: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OsvAffectedRange {
    #[serde(rename = "type")]
    pub range_type: String,
    pub repo: Option<String>,
    pub events: Vec<OsvAffectedRangeEvent>,
}

#[derive(Debug, Deserialize)]
pub struct OsvAffectedRangeEvent {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OsvReferences {
    pub url: Option<String>,
}

#[derive(Debug)]
pub struct OsvExtracted {
    pub details: Option<String>,
    pub patch_urls: Vec<String>,
}

impl OsvResponse {
    pub fn extract(&self) -> OsvExtracted {
        let patch_urls = self
            .affected
            .iter()
            .flat_map(|affected| affected.ranges.iter().flatten())
            .filter_map(|range| {
                let repo = range.repo.as_deref()?.trim_end_matches('/');
                let urls: Vec<String> = range
                    .events
                    .iter()
                    .filter_map(|event| event.fixed.as_deref())
                    .map(|hash| format!("{}/commit/{}", repo, hash))
                    .collect();
                Some(urls)
            })
            .flatten()
            .collect();

        OsvExtracted {
            details: self.details.clone(),
            patch_urls,
        }
    }
}
