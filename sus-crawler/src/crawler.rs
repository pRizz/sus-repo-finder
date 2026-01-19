//! Core crawler logic

use anyhow::Result;

/// The main crawler struct
pub struct Crawler {
    // Configuration and state will be added here
}

impl Crawler {
    /// Create a new crawler instance
    pub fn new() -> Self {
        Self {}
    }

    /// Start the crawling process
    pub async fn run(&self) -> Result<()> {
        // TODO: Implement crawler logic
        Ok(())
    }
}

impl Default for Crawler {
    fn default() -> Self {
        Self::new()
    }
}
