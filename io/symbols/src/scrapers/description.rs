use async_trait::async_trait;
use common::cve::Cve;
use common::symbol::{SourceLang, Symbol, SymbolConfidence};
use regex::Regex;
use std::sync::OnceLock;

use crate::extractor::Scraper;
use crate::scrapers::filters::is_likely_function_name;

fn function_name_pattern_regexes() -> &'static (Regex, Regex, Regex, Regex, Regex, Regex) {
    static REGEXES: OnceLock<(Regex, Regex, Regex, Regex, Regex, Regex)> = OnceLock::new();
    REGEXES.get_or_init(|| (
        Regex::new(r"\b([a-zA-Z_][a-zA-Z0-9_]{2,})\s*\(\)").unwrap(),
        Regex::new(r"`([a-zA-Z_][a-zA-Z0-9_]{2,})`").unwrap(),
        Regex::new(r#"(?i)(vulnerable function|affected function|function|method|symbol|API|call to)\s+[`"]?([a-zA-Z_][a-zA-Z0-9_]{2,})[`"]?"#, ).unwrap(),
        Regex::new(r#"(?i)[`"]?([a-zA-Z_][a-zA-Z0-9_]{2,})[`"]?\s+(vulnerable function|affected function|function|method|symbol|API|call from)"#,).unwrap(),
        Regex::new(r#"\s+(__[a-zA-Z0-9_]*|do_[a-zA-Z0-9_]*|sys_[a-zA-Z0-9_]*|ksys_[a-zA-Z0-9_]*|nf_[a-zA-Z0-9_]*|ip_[a-zA-Z0-9_]*|tcp_[a-zA-Z0-9_]*|udp_[a-zA-Z0-9_]*|xfs_[a-zA-Z0-9_]*|ext4_[a-zA-Z0-9_]*|btrfs_[a-zA-Z0-9_]*|sk_[a-zA-Z0-9_]*|net_[a-zA-Z0-9_]*|sctp_[a-zA-Z0-9_]*)"#).unwrap(),
        // "in <function>" pattern for kernel CVEs
        Regex::new(r"(?i)\bin\s+([a-zA-Z_][a-zA-Z0-9_]{3,})\b").unwrap(),
    ))
}

fn is_kernel_description(description: &str) -> bool {
    let lower = description.to_lowercase();
    lower.contains("kernel") || lower.contains("linux")
}

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
    let is_kernel = is_kernel_description(description);

    let (
        parenthesis_regex,
        backtick_regex,
        keyword_symbol_regex,
        symbol_keyword_regex,
        kernel_prefix_regex,
        in_function_regex,
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
            source_lang: SourceLang::Unknown,
        });
    }

    for cap in backtick_regex.captures_iter(description) {
        let name = &cap[1];
        // Reject file paths, version strings, digit-prefixed names
        if name.contains('/')
            || name.contains('.')
            || name.starts_with(|c: char| c.is_ascii_digit())
        {
            continue;
        }
        let m = cap.get(0).unwrap();
        let context = surrounding(description, m.start(), m.end(), 50);
        symbols.push(Symbol {
            name: name.to_string(),
            source: "description".into(),
            confidence: SymbolConfidence::Low,
            context,
            cve_id: cve_id.into(),
            source_lang: SourceLang::Unknown,
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
            source_lang: SourceLang::Unknown,
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
            source_lang: SourceLang::Unknown,
        });
    }

    for cap in kernel_prefix_regex.captures_iter(description) {
        let m = cap.get(0).unwrap();
        let context = surrounding(description, m.start(), m.end(), 50);
        // Boost to Medium for kernel CVEs since these prefixes are highly specific
        let confidence = if is_kernel {
            SymbolConfidence::Medium
        } else {
            SymbolConfidence::Low
        };
        symbols.push(Symbol {
            name: cap[1].to_string(),
            source: "description".into(),
            confidence,
            context,
            cve_id: cve_id.into(),
            source_lang: if is_kernel {
                SourceLang::Kernel
            } else {
                SourceLang::Unknown
            },
        });
    }

    // "in <function>" pattern — only for kernel CVEs to avoid excessive noise
    if is_kernel {
        for cap in in_function_regex.captures_iter(description) {
            let m = cap.get(0).unwrap();
            let context = surrounding(description, m.start(), m.end(), 50);
            symbols.push(Symbol {
                name: cap[1].to_string(),
                source: "description".into(),
                confidence: SymbolConfidence::Low,
                context,
                cve_id: cve_id.into(),
                source_lang: SourceLang::Kernel,
            });
        }
    }

    // Filter using shared filtering logic
    symbols
        .into_iter()
        .filter(|s| is_likely_function_name(&s.name))
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
