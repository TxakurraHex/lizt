use axum::response::Html;

pub async fn dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

// Entire frontend is embedded at compile time.
// What you see is what you "crate".
const DASHBOARD_HTML: &str = include_str!("../dashboard.html");
