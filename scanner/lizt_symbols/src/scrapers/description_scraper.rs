use crate::symbol_extractor::Scraper;
use async_trait::async_trait;
use lizt_core::cve::Cve;
use lizt_core::symbol::{Symbol, SymbolConfidence, SymbolType};
use regex::Regex;
use std::sync::OnceLock;

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

const STOP_WORDS: &[&str] = &[
    "the",
    "does",
    "when",
    "these",
    "those",
    "this",
    "that",
    "function",
    "method",
    "symbol",
    "helper",
    "streaming",
    "write",
    "read",
    "call",
    "error",
    "value",
    "buffer",
    "memory",
    "pointer",
    "integer",
    "string",
    "type",
    "true",
    "false",
    "null",
    "none",
];

pub struct DescriptionScraper;

#[async_trait]
impl Scraper for DescriptionScraper {
    fn name(&self) -> &str {
        "cve_description"
    }

    async fn scrape(&self, cve: &Cve) -> Vec<Symbol> {
        cve.descriptions
            .as_deref()
            .map(|desc| scrape_description(desc, &cve.id))
            .unwrap_or_default()
    }
}

pub fn scrape_description(description: &str, cve_id: &str) -> Vec<Symbol> {
    let mut symbols = Vec::new();

    let (
        parenthesis_regex,
        backtick_regex,
        keyword_symbol_regex,
        symbol_keyword_regex,
        kernel_prefix_regex,
    ) = function_name_pattern_regexes();

    for cap in parenthesis_regex.captures_iter(description) {
        let m = cap.get(0).unwrap();
        let context = surrounding(description, m.start(), m.end(), 50);
        symbols.push(Symbol {
            name: cap[1].to_string(),
            source: "description".into(),
            confidence: SymbolConfidence::Medium,
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
            confidence: SymbolConfidence::Low,
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
            confidence: SymbolConfidence::Low,
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
            confidence: SymbolConfidence::Low,
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
            confidence: SymbolConfidence::Low,
            context,
            cve_id: cve_id.into(),
            symbol_type: SymbolType::Function,
        });
    }

    // Filter out common, English-language words (unlikely to be functions)
    symbols
        .into_iter()
        .filter(|s| !STOP_WORDS.contains(&s.name.to_lowercase().as_str()))
        .collect()
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
