//! Sus Core - Shared types, database models, and queries
//!
//! This crate provides the foundational types and database access layer
//! used by both the crawler and dashboard applications.

pub mod db;
pub mod models;
pub mod types;

pub use db::Database;
pub use models::*;
pub use types::*;
