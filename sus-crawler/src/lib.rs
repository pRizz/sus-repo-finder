//! Sus Crawler Library
//!
//! This library provides the crates.io API client and related utilities
//! for crawling crates.io and analyzing crate sources.

pub mod crates_io;

pub use crates_io::{CrateMetadata, CrateResponse, CratesIoClient, CratesIoError};
