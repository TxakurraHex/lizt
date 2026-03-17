use crate::extractor::Scraper;
use crate::scrapers::description::scrape_description;
use async_trait::async_trait;
use common::cve::{Cve, CveRef};
use common::symbol::{SourceLang, Symbol, SymbolConfidence};
use io_nvd::client::LiztClient;
use io_nvd::response::github::GitHubIssue;
use regex::Regex;
use std::sync::{Arc, OnceLock};

fn diff_regexes() -> &'static (Regex, Regex, Regex, Regex, Regex, Regex) {
    static REGEXES: OnceLock<(Regex, Regex, Regex, Regex, Regex, Regex)> = OnceLock::new();
    REGEXES.get_or_init(|| (
        Regex::new(r"^[-+]\s*(?:static\s+)?(?:inline\s+)?(?:const\s+)?(\w+(?:\s*\*)*)\s+([a-zA-Z_][a-zA-Z0-9_]+)\s*\([^)]*\)\s*(?:\{|;)?", ).unwrap(),
        Regex::new(r"^[-+]\s*def\s+([a-zA-Z_][a-zA-Z0-9_]+)\s*\(").unwrap(),
        Regex::new(r"^[-+]\s*(?:public|private|protected)?\s*(?:static)?\s*\w+\s+([a-zA-Z_][a-zA-Z0-9_]+)\s*\(", ).unwrap(),
        Regex::new(r"^[-+]\s*(?:pub\s+)?(?:async\s+)?fn\s+([a-zA-Z_][a-zA-Z0-9_]+)\s*\(").unwrap(),
        Regex::new(r"^[-+]\s*func\s+(?:\([^)]*\)\s+)?([a-zA-Z_][a-zA-Z0-9_]+)\s*\(").unwrap(),
        Regex::new(r"\b([a-zA-Z_][a-zA-Z0-9_]{2,})\s*\(").unwrap(),
    ))
}
pub struct GithubScraper {
    client: Arc<LiztClient>,
}

impl GithubScraper {
    pub fn new(client: Arc<LiztClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl Scraper for GithubScraper {
    fn name(&self) -> &str {
        "github"
    }

    async fn scrape(&self, cve: &Cve) -> Vec<Symbol> {
        let Some(references) = &cve.refs else {
            return vec![];
        };

        // Prioritise Patch-tagged refs first; skip refs tagged only with low-signal tags.
        let ordered_refs = prioritize_refs(references);

        let results = futures::future::join_all(ordered_refs.iter().map(|r| async {
            tokio::join!(
                self.client.request_patch(&r.url),
                self.client.request_github_issue(&r.url)
            )
        }))
        .await;

        let mut symbols = vec![];
        for (r, (diff, issue)) in ordered_refs.iter().zip(results) {
            if let Some(git_diff) = diff {
                symbols.extend(scrape_diff(git_diff, &r.url, &cve.id));
            }
            if let Some(github_issue) = issue {
                symbols.extend(scrape_github_issue(github_issue, &r.url, &cve.id));
            }
        }
        symbols
    }
}

/// Returns refs ordered: Patch-tagged first, then untagged/other, skipping refs whose only
/// tags are low-signal (Press/Media Coverage, Exploit).
fn prioritize_refs(refs: &[CveRef]) -> Vec<&CveRef> {
    const SKIP_ONLY: &[&str] = &["Press/Media Coverage", "Exploit"];

    let skip = |r: &&CveRef| -> bool {
        let tags: Vec<_> = r.tags.iter().flatten().collect();
        !tags.is_empty() && tags.iter().all(|t| SKIP_ONLY.contains(&t.as_str()))
    };

    let mut patch: Vec<&CveRef> = refs
        .iter()
        .filter(|r| r.tags.iter().flatten().any(|t| t == "Patch"))
        .collect();
    let mut other: Vec<&CveRef> = refs
        .iter()
        .filter(|r| !r.tags.iter().flatten().any(|t| t == "Patch") && !skip(r))
        .collect();
    patch.append(&mut other);
    patch
}

pub fn scrape_diff(diff_string: String, commit_url: &str, cve_id: &String) -> Vec<Symbol> {
    let mut symbols = vec![];
    let source = format!("commit_diff: {}", commit_url);

    let (
        c_func_regex,
        python_def_regex,
        java_method_regex,
        rust_fn_regex,
        go_func_regex,
        func_call_regex,
    ) = diff_regexes();
    const IGNORED_KEYWORDS: &[&str] = &[
        "if", "for", "while", "switch", "return", "sizeof", "malloc", "free",
    ];
    let lines: Vec<&str> = diff_string.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let context_range = |before: usize, after: usize| -> String {
            let lo = i.saturating_sub(before);
            let hi = (i + after + 1).min(lines.len());
            lines[lo..hi].join("\n")
        };

        if let Some(cap) = c_func_regex.captures(line) {
            symbols.push(Symbol {
                name: cap[2].to_string(),
                source: source.clone(),
                confidence: SymbolConfidence::High,
                context: context_range(2, 2),
                cve_id: cve_id.into(),

                source_lang: SourceLang::C,
            });
        }

        if let Some(cap) = python_def_regex.captures(line) {
            symbols.push(Symbol {
                name: cap[1].to_string(),
                source: source.clone(),
                confidence: SymbolConfidence::High,
                context: context_range(2, 2),
                cve_id: cve_id.into(),

                source_lang: SourceLang::Python,
            });
        }

        if let Some(cap) = java_method_regex.captures(line) {
            symbols.push(Symbol {
                name: cap[1].to_string(),
                source: source.clone(),
                confidence: SymbolConfidence::High,
                context: context_range(2, 2),
                cve_id: cve_id.into(),

                source_lang: SourceLang::Java,
            });
        }

        if let Some(cap) = rust_fn_regex.captures(line) {
            symbols.push(Symbol {
                name: cap[1].to_string(),
                source: source.clone(),
                confidence: SymbolConfidence::High,
                context: context_range(2, 2),
                cve_id: cve_id.into(),

                source_lang: SourceLang::Rust,
            });
        }

        if let Some(cap) = go_func_regex.captures(line) {
            symbols.push(Symbol {
                name: cap[1].to_string(),
                source: source.clone(),
                confidence: SymbolConfidence::High,
                context: context_range(2, 2),
                cve_id: cve_id.into(),

                source_lang: SourceLang::Go,
            });
        }

        if line.starts_with("+") || line.starts_with("-") {
            for cap in func_call_regex.captures_iter(line) {
                let name = &cap[1];
                if !IGNORED_KEYWORDS.contains(&name) {
                    symbols.push(Symbol {
                        name: name.to_string(),
                        source: source.clone(),
                        confidence: SymbolConfidence::Medium,
                        context: context_range(1, 1),
                        cve_id: cve_id.into(),

                        source_lang: SourceLang::Unknown,
                    });
                }
            }
        }
    }
    symbols
}

fn scrape_github_issue(issue: GitHubIssue, url: &str, cve_id: &str) -> Vec<Symbol> {
    let text = format!(
        "{} {}",
        issue.title.unwrap_or_default(),
        issue.body.unwrap_or_default()
    );
    let mut symbols = scrape_description(&text, cve_id);
    let source = format!("github_issue: {}", url);
    for symbol in &mut symbols {
        symbol.source = source.clone();
    }
    symbols
}
