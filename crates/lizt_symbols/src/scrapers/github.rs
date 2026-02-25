use std::sync::OnceLock;
use regex::Regex;
use lizt_core::cve::Cve;
use lizt_rest::nvd_cve::GitHubIssue;
use lizt_rest::rest::LiztRestClient;
use crate::extractor::Scraper;
use crate::symbol::{Symbol, Confidence, SymbolType};
use crate::scrapers::description::scrape_description;

fn diff_regexes() -> &'static (Regex, Regex, Regex, Regex) {
    static REGEXES: OnceLock<(Regex, Regex, Regex, Regex)> = OnceLock::new();
    REGEXES.get_or_init(|| (
        Regex::new(r"^[-+]\s*(?:static\s+)?(?:inline\s+)?(?:const\s+)?(\w+(?:\s*\*)*)\s+([a-zA-Z_][a-zA-Z0-9_]+)\s*\([^)]*\)\s*(?:\{|;)?", ).unwrap(),
        Regex::new(r"^[-+]\s*def\s+([a-zA-Z_][a-zA-Z0-9_]+)\s*\(").unwrap(),
        Regex::new(r"^[-+]\s*(?:public|private|protected)?\s*(?:static)?\s*\w+\s+([a-zA-Z_][a-zA-Z0-9_]+)\s*\(", ).unwrap(),
        Regex::new(r"\b([a-zA-Z_][a-zA-Z0-9_]{2,})\s*\(").unwrap(),
    ))
}
pub struct GithubScraper;

impl Scraper for GithubScraper {
    fn name(&self) -> &str {
        "github"
    }

    fn scrape(&self, cve: &Cve) -> Vec<Symbol> {
        let mut symbols = vec![];
        let api_key = std::env::var("API_KEY").ok();
        let rest_client = LiztRestClient::new(api_key);

        if let Some(references) = &cve.references {
            for reference in references {
                if let Some(git_diff) = rest_client.request_github_commit_diff(&reference.url) {
                    symbols.extend(scrape_diff(git_diff, &reference.url, &cve.id));
                }
                if let Some(github_issue) = rest_client.request_github_issue(&reference.url) {
                    symbols.extend(scrape_github_issue(github_issue, &reference.url, &cve.id));
                }
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
                confidence: Confidence::High,
                context: context_range(2, 2),
                cve_id: cve_id.into(),
                symbol_type: SymbolType::Function,
            });
        }

        if let Some(cap) = python_def_regex.captures(line) {
            symbols.push(Symbol {
                name: cap[1].to_string(),
                source: source.clone(),
                confidence: Confidence::High,
                context: context_range(2, 2),
                cve_id: cve_id.into(),
                symbol_type: SymbolType::Function,
            });
        }

        if let Some(cap) = java_method_regex.captures(line) {
            symbols.push(Symbol {
                name: cap[1].to_string(),
                source: source.clone(),
                confidence: Confidence::High,
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
                        confidence: Confidence::Medium,
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
    let text = format!("{} {}", issue.title.unwrap_or_default(), issue.body.unwrap_or_default());
    let mut symbols = scrape_description(&text, cve_id);
    let source = format!("github_issue: {}", url);
    for symbol in &mut symbols {
        symbol.source = source.clone();
    }
    symbols
}