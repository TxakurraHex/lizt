use async_trait::async_trait;
use common::cve::Cve;
use common::symbol::{SourceLang, Symbol, SymbolConfidence};
use std::collections::HashMap;

use crate::scrapers::filters::is_likely_function_name;

#[async_trait]
pub trait Scraper: Send + Sync {
    fn name(&self) -> &str;
    async fn scrape(&self, cve: &Cve) -> Vec<Symbol>;
}

pub struct CveSymbolExtractor {
    pub scrapers: Vec<Box<dyn Scraper>>,
    pub symbols: Vec<Symbol>,
}

impl CveSymbolExtractor {
    pub fn new(scrapers: Vec<Box<dyn Scraper>>) -> Self {
        Self {
            scrapers,
            symbols: Vec::new(),
        }
    }

    pub async fn extract_symbols(&mut self, cves: &[Cve]) {
        let all_symbols: Vec<Symbol> = futures::future::join_all(cves.iter().map(|cve| {
            let scrapers = &self.scrapers;
            async move {
                futures::future::join_all(scrapers.iter().map(|scraper| scraper.scrape(cve))).await
            }
        }))
        .await
        .into_iter()
        .flatten()
        .flatten()
        .collect();

        // Group by (name, cve_id) — track all distinct source prefixes for confidence boosting
        let mut groups: HashMap<String, (Symbol, Vec<String>)> = HashMap::new();

        for symbol in all_symbols {
            let key = format!("{}_{}", symbol.name, symbol.cve_id);
            let source_prefix = source_prefix(&symbol.source);

            groups
                .entry(key)
                .and_modify(|(existing, sources)| {
                    if !sources.contains(&source_prefix) {
                        sources.push(source_prefix.clone());
                    }
                    if symbol.confidence > existing.confidence {
                        *existing = symbol.clone();
                    }
                })
                .or_insert_with(|| (symbol, vec![source_prefix]));
        }

        // Apply multi-source confidence boosting: if 2+ distinct source types found the
        // same symbol, boost confidence by one level.
        self.symbols = groups
            .into_values()
            .map(|(mut sym, sources)| {
                if sources.len() >= 2 {
                    sym.confidence = sym.confidence.boost();
                }
                sym
            })
            .collect();
    }

    /// Filter out symbols unlikely to be real probe targets.
    pub fn validate(&mut self) {
        self.symbols.retain(|s| {
            is_likely_function_name(&s.name) && s.confidence >= SymbolConfidence::Medium
        });
    }

    /// Infer source language from CVE data when the scraper left it as Unknown.
    pub fn infer_languages(&mut self, cves: &[Cve]) {
        // Build a map of cve_id -> inferred language from CPE/description data
        let mut lang_hints: HashMap<String, SourceLang> = HashMap::new();
        for cve in cves {
            if let Some(cpes) = &cve.cpes {
                for cve_cpe in cpes {
                    if cve_cpe.cpe.product == "linux_kernel" || cve_cpe.cpe.vendor == "linux" {
                        lang_hints.insert(cve.id.clone(), SourceLang::Kernel);
                        break;
                    }
                }
            }
            // Description-based hints (only if no CPE hint already set)
            if !lang_hints.contains_key(&cve.id)
                && let Some(desc) = &cve.descriptions
            {
                let lower = desc.to_lowercase();
                if lower.contains("openssl")
                    || lower.contains("glibc")
                    || lower.contains("libcurl")
                    || lower.contains("libc")
                {
                    lang_hints.insert(cve.id.clone(), SourceLang::C);
                }
            }
        }

        for symbol in &mut self.symbols {
            if symbol.source_lang == SourceLang::Unknown
                && let Some(lang) = lang_hints.get(&symbol.cve_id)
            {
                symbol.source_lang = lang.clone();
            }
        }
    }
}

/// Extract the source type prefix for grouping (e.g., "description", "commit_diff", "github_issue").
fn source_prefix(source: &str) -> String {
    source
        .split(':')
        .next()
        .unwrap_or(source)
        .trim()
        .to_string()
}
