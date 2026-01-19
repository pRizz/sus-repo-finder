//! Sus Detector - Pattern detection for suspicious Rust code
//!
//! This crate provides the core pattern detection logic for analyzing
//! build.rs files and proc-macro crates for potentially malicious patterns.

pub mod detector;
pub mod patterns;

pub use detector::Detector;
pub use patterns::*;
