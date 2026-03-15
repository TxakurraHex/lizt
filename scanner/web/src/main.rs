mod api;
mod html;

use axum::{Router, routing::get};
use log::info;
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    load_config();

    log4rs::init_file("/etc/lizt/lizt_web_log4rs.yaml", Default::default())
        .unwrap_or_else(|_| eprintln!("log4rs config not found, using stderr"));

    let pool = db::connect().await?;
    let cors = CorsLayer::new().allow_origin(Any);

    let app = Router::new()
        // Dashboard HTML (single-page app shell)
        .route("/", get(html::dashboard))
        // REST API
        .route("/api/findings", get(api::findings::list))
        .route("/api/cve/{cve_id}", get(api::cve::detail))
        .route("/api/observation", get(api::observations::list))
        .route("/api/inventory", get(api::inventory::list))
        .layer(cors)
        .with_state(pool);

    let port: u16 = std::env::var("LIZT_WEB_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("liztening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

fn load_config() {
    let Some(home) = std::env::var_os("HOME") else {
        return;
    };
    let path = std::path::Path::new(&home).join(".lizt_config");
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return;
    };
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            // Don't overwrite values already set in the environment
            if std::env::var(k).is_err() {
                unsafe {
                    std::env::set_var(k, v);
                }
            }
        }
    }
}
