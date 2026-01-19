//! Sus Crawler - Crates.io scanner for suspicious patterns
//!
//! This application crawls crates.io, downloads crate sources, and analyzes
//! them for suspicious patterns in build.rs files and proc-macro crates.

use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api;
mod crawler;
mod templates;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sus_crawler=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Sus Crawler...");

    // Get configuration from environment
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite:./data/sus-repo-finder.db".to_string());
    let port: u16 = std::env::var("CRAWLER_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3001);

    // Initialize database
    let db = sus_core::Database::new(&database_url).await?;
    tracing::info!("Connected to database");

    // Start the web server
    let app = api::create_router(db);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    tracing::info!("Crawler portal listening on http://localhost:{}", port);

    axum::serve(listener, app).await?;

    Ok(())
}
