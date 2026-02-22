use crate::symbol::Symbol;
use std::collections::HashSet;
use lizt_core::cve::{Cve, CveDescription, CveReference};

pub trait Scraper {
    fn name(&self) -> &str;
    fn scrape(&self, cve: &Cve) -> Vec<Symbol>;
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

    pub fn extract_symbols(&mut self, cves: &Vec<Cve>) {
        let mut seen: HashSet<String> = HashSet::new();
        for scraper in &self.scrapers {
            for cve in cves {
                let symbols = scraper.scrape(cve);
                for symbol in symbols {
                    if seen.insert(format!("{}_{}", symbol.name, symbol.cve_id)) {
                        self.symbols.push(symbol);
                    }
                }
            }
        }
    }
}