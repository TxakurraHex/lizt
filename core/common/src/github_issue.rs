use serde::Deserialize;
#[derive(Deserialize)]
pub struct GibHubIssue {
    pub title: Option<String>,
    pub body: Option<String>,
}
