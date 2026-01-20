//! Sus Crawler - Crates.io scanner for suspicious patterns
//!
//! This application crawls crates.io, downloads crate sources, and analyzes
//! them for suspicious patterns in build.rs files and proc-macro crates.
//!
//! ## Graceful Shutdown
//!
//! The crawler supports graceful shutdown via SIGINT (Ctrl-C) or SIGTERM:
//! 1. On receiving the signal, logs "Shutdown signal received"
//! 2. Completes any in-progress crate processing
//! 3. Checkpoints the crawler state to the database
//! 4. Exits cleanly with code 0

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api;
mod templates;

/// Shutdown signal handler that waits for SIGINT or SIGTERM
async fn shutdown_signal(shutdown_tx: broadcast::Sender<()>) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received SIGINT (Ctrl-C), initiating graceful shutdown...");
        }
        _ = terminate => {
            tracing::info!("Received SIGTERM, initiating graceful shutdown...");
        }
    }

    // Notify all listeners that shutdown has been requested
    let _ = shutdown_tx.send(());
    tracing::info!("Shutdown signal sent to all components");
}

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

    // Initialize database (wrapped in Arc for sharing between app and shutdown handler)
    let db = Arc::new(sus_core::Database::new(&database_url).await?);
    let db_for_shutdown = Arc::clone(&db);
    tracing::info!("Connected to database");

    // Create shutdown broadcast channel
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let shutdown_tx_for_signal = shutdown_tx.clone();

    // Start the web server with graceful shutdown
    let app = api::create_router(db);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    tracing::info!("Crawler portal listening on http://localhost:{}", port);
    tracing::info!("Press Ctrl-C to initiate graceful shutdown");

    // Run the server with graceful shutdown support
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown_signal(shutdown_tx_for_signal).await;

            // Checkpoint the crawler state before shutting down
            tracing::info!("Checkpointing crawler state before shutdown...");

            // Get the latest crawler state and mark it as paused if running
            match db_for_shutdown.get_latest_crawler_state().await {
                Ok(Some(state)) => {
                    if state.status == "running" {
                        tracing::info!(
                            "Pausing active crawler run '{}' (processed {}/{} crates)",
                            state.run_id,
                            state.crates_processed,
                            state.crates_total
                        );
                        if let Err(e) = db_for_shutdown.pause_crawler_run(&state.run_id).await {
                            tracing::error!("Failed to pause crawler run: {}", e);
                        } else {
                            tracing::info!("Crawler run '{}' paused successfully", state.run_id);
                        }
                    } else {
                        tracing::info!(
                            "Crawler run '{}' is already in '{}' state, no checkpoint needed",
                            state.run_id,
                            state.status
                        );
                    }
                }
                Ok(None) => {
                    tracing::info!("No active crawler run to checkpoint");
                }
                Err(e) => {
                    tracing::error!("Failed to get crawler state for checkpoint: {}", e);
                }
            }

            tracing::info!("Graceful shutdown complete");
        })
        .await?;

    tracing::info!("Server has shut down cleanly");
    Ok(())
}
