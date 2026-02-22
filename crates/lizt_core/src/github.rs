use serde::Deserialize;
#[derive(Deserialize)]
pub struct GibHubIssue {
    title: Option<String>,
    body: Option<String>,
}