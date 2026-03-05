use crate::scrapers::description_scraper::scrape_description;
use crate::symbol_extractor::Scraper;
use async_trait::async_trait;
use lizt_core::cve::Cve;
use lizt_core::symbol::{Symbol, SymbolConfidence, SymbolType};
use lizt_rest::nvd::github_response::GitHubIssue;
use lizt_rest::rest_client::LiztRestClient;
use regex::Regex;
use std::sync::{Arc, OnceLock};

fn diff_regexes() -> &'static (Regex, Regex, Regex, Regex) {
    static REGEXES: OnceLock<(Regex, Regex, Regex, Regex)> = OnceLock::new();
    REGEXES.get_or_init(|| (
        Regex::new(r"^[-+]\s*(?:static\s+)?(?:inline\s+)?(?:const\s+)?(\w+(?:\s*\*)*)\s+([a-zA-Z_][a-zA-Z0-9_]+)\s*\([^)]*\)\s*(?:\{|;)?", ).unwrap(),
        Regex::new(r"^[-+]\s*def\s+([a-zA-Z_][a-zA-Z0-9_]+)\s*\(").unwrap(),
        Regex::new(r"^[-+]\s*(?:public|private|protected)?\s*(?:static)?\s*\w+\s+([a-zA-Z_][a-zA-Z0-9_]+)\s*\(", ).unwrap(),
        Regex::new(r"\b([a-zA-Z_][a-zA-Z0-9_]{2,})\s*\(").unwrap(),
    ))
}
pub struct GithubScraper {
    client: Arc<LiztRestClient>,
}

impl GithubScraper {
    pub fn new(client: Arc<LiztRestClient>) -> Self {
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

        let results = futures::future::join_all(references.iter().map(|url| async {
            tokio::join!(
                self.client.request_github_commit_diff(url),
                self.client.request_github_issue(url)
            )
        }))
        .await;

        let mut symbols = vec![];
        for (url, (diff, issue)) in references.iter().zip(results) {
            if let Some(git_diff) = diff {
                symbols.extend(scrape_diff(git_diff, url, &cve.id));
            }
            if let Some(github_issue) = issue {
                symbols.extend(scrape_github_issue(github_issue, url, &cve.id));
            }
        }
        symbols
    }
}

fn scrape_diff(diff_string: String, commit_url: &String, cve_id: &String) -> Vec<Symbol> {
    let mut symbols = vec![];
    let source = format!("commit_diff: {}", commit_url);

    let (c_func_regex, python_def_regex, java_method_regex, func_call_regex) = diff_regexes();
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
                symbol_type: SymbolType::Function,
            });
        }

        if let Some(cap) = python_def_regex.captures(line) {
            symbols.push(Symbol {
                name: cap[1].to_string(),
                source: source.clone(),
                confidence: SymbolConfidence::High,
                context: context_range(2, 2),
                cve_id: cve_id.into(),
                symbol_type: SymbolType::Function,
            });
        }

        if let Some(cap) = java_method_regex.captures(line) {
            symbols.push(Symbol {
                name: cap[1].to_string(),
                source: source.clone(),
                confidence: SymbolConfidence::High,
                context: context_range(2, 2),
                cve_id: cve_id.into(),
                symbol_type: SymbolType::Function,
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
                        symbol_type: SymbolType::Function,
                    })
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
