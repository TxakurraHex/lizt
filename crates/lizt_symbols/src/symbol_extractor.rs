use async_trait::async_trait;
use lizt_core::cve::Cve;
use lizt_core::symbol::Symbol;
use std::collections::HashSet;

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
        let mut seen: HashSet<String> = HashSet::new();
        for scraper in &self.scrapers {
            for cve in cves {
                println!("Scraping {} with {}", cve.id, scraper.name());
                let symbols = scraper.scrape(cve).await;

                for symbol in symbols {
                    if seen.insert(format!("{}_{}", symbol.name, symbol.cve_id)) {
                        self.symbols.push(symbol);
                    }
                }
            }
        }
    }
}
