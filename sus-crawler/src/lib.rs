//! Sus Crawler Library
//!
//! This library provides the crates.io API client and related utilities
//! for crawling crates.io and analyzing crate sources.

pub mod crates_io;
pub mod crawler;
pub mod downloader;

pub use crates_io::{CrateMetadata, CrateResponse, CratesIoClient, CratesIoError};
pub use crawler::{CrateProcessResult, Crawler, CrawlerConfig};
pub use downloader::{CrateDownloader, DownloadError, ExtractedCrate};
