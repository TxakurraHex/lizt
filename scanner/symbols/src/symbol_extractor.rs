use async_trait::async_trait;
use common::cve::Cve;
use common::symbol::Symbol;
use std::collections::HashMap;

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
        let mut best: HashMap<String, Symbol> = HashMap::new();
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

        for symbol in all_symbols {
            let key = format!("{}_{}", symbol.name, symbol.cve_id);
            best.entry(key)
                .and_modify(|existing| {
                    if symbol.confidence > existing.confidence {
                        *existing = symbol.clone();
                    }
                })
                .or_insert(symbol);
        }
        self.symbols = best.into_values().collect();
    }
}
