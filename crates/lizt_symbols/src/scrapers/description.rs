use std::error::Error;
use std::sync::OnceLock;
use regex::Regex;
use lizt_core::cve::Cve;
use crate::symbol::{Confidence, Symbol, SymbolType};
use crate::extractor::Scraper;

fn function_name_pattern_regexes() -> &'static (Regex, Regex, Regex, Regex, Regex) {
    static REGEXES: OnceLock<(Regex, Regex, Regex, Regex, Regex)> = OnceLock::new();
    REGEXES.get_or_init(|| (
        Regex::new(r"\b([a-zA-Z_][a-zA-Z0-9_]{2,})\s*\(\)").unwrap(),
        Regex::new(r"`([a-zA-Z_][a-zA-Z0-9_]{2,})`").unwrap(),
        Regex::new(r#"(?i)(vulnerable function|affected function|function|method|symbol|API|call to)\s+[`"]?([a-zA-Z_][a-zA-Z0-9_]{2,})[`"]?"#, ).unwrap(),
        Regex::new(r#"(?i)[`"]?([a-zA-Z_][a-zA-Z0-9_]{2,})[`"]?\s+(vulnerable function|affected function|function|method|symbol|API|call from)"#,).unwrap(),
        Regex::new(r#"\s+(__[a-zA-Z0-9_]*|do_[a-zA-Z0-9_]*|sys_[a-zA-Z0-9_]*|ksys_[a-zA-Z0-9_]*)"#).unwrap()
    ))
}

pub struct DescriptionScraper;

impl Scraper for DescriptionScraper {
    fn name(&self) -> &str {
        "cve_description"
    }

    fn scrape(&self, cve: &Cve) -> Vec<Symbol> {
        let mut symbols = Vec::new();
        if let Some(descriptions) = &cve.descriptions {
            for description in descriptions {
                if description.lang == "en" {
                    symbols = scrape_description(description.value.as_str(), &cve.id);
                }
            }
        }
        symbols
    }
}

pub fn scrape_description(description: &str, cve_id: &str) -> Vec<Symbol> {
    let mut symbols = Vec::new();

    let (
        parenthesis_regex,
        backtick_regex,
        keyword_symbol_regex,
        symbol_keyword_regex,
        kernel_prefix_regex) = function_name_pattern_regexes();

    for cap in parenthesis_regex.captures_iter(description) {
        let m = cap.get(0).unwrap();
        let context = surrounding(description, m.start(), m.end(), 50);
        symbols.push(Symbol {
            name: cap[1].to_string(),
            source: "description".into(),
            confidence: Confidence::Medium,
            context,
            cve_id: cve_id.into(),
            symbol_type: SymbolType::Function,
        });
    }

    for cap in backtick_regex.captures_iter(description) {
        let m = cap.get(0).unwrap();
        let context = surrounding(description, m.start(), m.end(), 50);
        symbols.push(Symbol {
            name: cap[1].to_string(),
            source: "description".into(),
            confidence: Confidence::Low,
            context,
            cve_id: cve_id.into(),
            symbol_type: SymbolType::Function,
        });
    }

    for cap in keyword_symbol_regex.captures_iter(description) {
        let m = cap.get(0).unwrap();
        let context = surrounding(description, m.start(), m.end(), 50);
        symbols.push(Symbol {
            name: cap[2].to_string(),
            source: "description".into(),
            confidence: Confidence::Low,
            context,
            cve_id: cve_id.into(),
            symbol_type: SymbolType::Function,
        });
    }

    for cap in symbol_keyword_regex.captures_iter(description) {
        let m = cap.get(0).unwrap();
        let context = surrounding(description, m.start(), m.end(), 50);
        symbols.push(Symbol {
            name: cap[1].to_string(),
            source: "description".into(),
            confidence: Confidence::Low,
            context,
            cve_id: cve_id.into(),
            symbol_type: SymbolType::Function,
        });
    }

    for cap in kernel_prefix_regex.captures_iter(description) {
        let m = cap.get(0).unwrap();
        let context = surrounding(description, m.start(), m.end(), 50);
        symbols.push(Symbol {
            name: cap[1].to_string(),
            source: "description".into(),
            confidence: Confidence::Low,
            context,
            cve_id: cve_id.into(),
            symbol_type: SymbolType::Function,
        });
    }

    symbols
}

/// Return a substring of `text` expanded by `pad` chars on each side of `[start, end)`.
fn surrounding(text: &str, start: usize, end: usize, pad: usize) -> String {
    let lo = start.saturating_sub(pad);
    let hi = (end + pad).min(text.len());
    // Snap to char boundaries
    let lo = text.floor_char_boundary(lo);
    let hi = text.ceil_char_boundary(hi);
    text[lo..hi].trim().to_string()
}