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

struct MatchRule<'a> {
    regex: &'a Regex,
    name_group: usize,
    confidence: SymbolConfidence,
    source_lang: SourceLang,
    filter: fn(&str) -> bool,
}

fn backtick_filter(name: &str) -> bool {
    // Reject file paths, version strings, digit-prefixed names
    !name.contains('/') && !name.contains('.') && !name.starts_with(|c: char| c.is_ascii_digit())
}

fn in_regex_filter(name: &str) -> bool {
    if !is_likely_function_name(name) {
        return false;
    }

    if name.len() < 4 {
        return false;
    }

    if is_kernel_description(name) {
        return true;
    }

    if name.contains('_') {
        return true;
    }

    let has_case_transition = name
        .as_bytes()
        .windows(2)
        .any(|w| w[0].is_ascii_lowercase() && w[1].is_ascii_uppercase());
    if has_case_transition {
        return true;
    }

    const KNOWN_API_PREFIXES: &[&str] = &[
        // OpenSSL
        "SSL_",
        "EVP_",
        "BN_",
        "BIO_",
        "RSA_",
        "EC_",
        "X509_",
        "PEM_",
        "HMAC_",
        "PKCS",
        "ASN1_",
        "OSSL_",
        // zlib
        "inflate",
        "deflate",
        "compress",
        "uncompress",
        // libexpat / libxml2
        "XML_",
        "xml",
        "Html",
        // glibc / POSIX
        "__libc_",
        "__GI_",
        // GnuTLS
        "gnutls_",
        // libcurl
        "curl_",
        "Curl_",
        // libssh
        "ssh_",
        // kernel (double-underscore already passes, but explicit)
        "__",
    ];
    if KNOWN_API_PREFIXES.iter().any(|p| name.starts_with(p)) {
        return true;
    }

    false
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

    let rules = [
        MatchRule {
            regex: parenthesis_regex,
            name_group: 1,
            confidence: SymbolConfidence::Medium,
            source_lang: SourceLang::Unknown,
            filter: |_| true,
        },
        MatchRule {
            regex: backtick_regex,
            name_group: 1,
            confidence: SymbolConfidence::Low,
            source_lang: SourceLang::Unknown,
            filter: backtick_filter,
        },
        MatchRule {
            regex: keyword_symbol_regex,
            name_group: 2,
            confidence: SymbolConfidence::Low,
            source_lang: SourceLang::Unknown,
            filter: |_| true,
        },
        MatchRule {
            regex: symbol_keyword_regex,
            name_group: 1,
            confidence: SymbolConfidence::Low,
            source_lang: SourceLang::Unknown,
            filter: |_| true,
        },
        // Boost to Medium for kernel CVEs since these prefixes are highly specific
        MatchRule {
            regex: kernel_prefix_regex,
            name_group: 1,
            confidence: if is_kernel {
                SymbolConfidence::Medium
            } else {
                SymbolConfidence::Low
            },
            source_lang: if is_kernel {
                SourceLang::Kernel
            } else {
                SourceLang::Unknown
            },
            filter: |_| true,
        },
        // "in <function>" pattern — only for kernel CVEs to avoid excessive noise
        MatchRule {
            regex: in_function_regex,
            name_group: 1,
            confidence: SymbolConfidence::Low,
            source_lang: if is_kernel {
                SourceLang::Kernel
            } else {
                SourceLang::C
            },
            filter: in_regex_filter,
        },
    ];

    for rule in &rules {
        for cap in rule.regex.captures_iter(description) {
            let name = &cap[rule.name_group];
            if !(rule.filter)(name) {
                continue;
            }
            let m = cap.get(0).unwrap();
            let context = surrounding(description, m.start(), m.end(), 50);
            symbols.push(Symbol {
                name: name.to_string(),
                source: "description".into(),
                confidence: rule.confidence.clone(),
                context,
                cve_id: cve_id.into(),
                source_lang: rule.source_lang.clone(),
                binary_path: None,
                probe_type: None,
                validated: false,
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
