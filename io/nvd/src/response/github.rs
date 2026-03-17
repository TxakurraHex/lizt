use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct GitHubIssue {
    pub title: Option<String>,
    pub body: Option<String>,
}
