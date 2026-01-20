//! Main detector implementation
//!
//! This module implements pattern detection for suspicious code in Rust build scripts
//! and proc-macro crates. It uses the `syn` crate for AST parsing and visitors.

use crate::patterns::{default_severity, extract_snippet, Finding};
use sus_core::IssueType;
use syn::visit::Visit;
use syn::{Expr, ExprCall, ExprMethodCall, ExprPath, ItemUse, UseTree};

/// Network-related module and function patterns to detect.
/// These indicate potential network I/O in build scripts which could be suspicious.
const NETWORK_PATTERNS: &[&str] = &[
    // Popular HTTP clients
    "reqwest",
    "hyper",
    "ureq",
    "attohttpc",
    "isahc",
    "surf",
    // Standard library networking
    "std::net",
    "TcpStream",
    "TcpListener",
    "UdpSocket",
    // Low-level networking
    "curl",
    "curl_sys",
    "socket2",
    "mio",
    // Async runtime networking
    "tokio::net",
    "async_std::net",
];

/// File system access patterns to detect.
/// These indicate file I/O operations in build scripts which could be suspicious
/// if accessing files outside the expected build directory.
const FILE_ACCESS_PATTERNS: &[&str] = &[
    // Standard library file I/O
    "std::fs",
    "std::io",
    "File",
    "OpenOptions",
    // Common file operations
    "read_to_string",
    "write",
    "create",
    "remove_file",
    "remove_dir",
    "remove_dir_all",
    "copy",
    "rename",
    "metadata",
    "read_dir",
    "create_dir",
    "create_dir_all",
    // Path operations that might indicate file access
    "canonicalize",
    "read_link",
    "symlink",
    "hard_link",
    // Async file I/O
    "tokio::fs",
    "async_std::fs",
];

/// Specific file access method names that are suspicious in build scripts
const FILE_ACCESS_METHODS: &[&str] = &[
    "open",
    "create",
    "write",
    "write_all",
    "read",
    "read_to_string",
    "read_to_end",
    "read_dir",
    "remove_file",
    "remove_dir",
    "remove_dir_all",
    "create_dir",
    "create_dir_all",
    "copy",
    "rename",
    "metadata",
    "exists",
    "is_file",
    "is_dir",
    "canonicalize",
];

/// The main pattern detector
pub struct Detector {
    // Configuration options can be added here
}

impl Detector {
    /// Create a new detector with default settings
    pub fn new() -> Self {
        Self {}
    }

    /// Analyze Rust source code for suspicious patterns
    pub fn analyze(&self, source: &str, file_path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Try to parse the source code
        match syn::parse_file(source) {
            Ok(syntax_tree) => {
                // Run all pattern detectors
                findings.extend(self.detect_network_calls(&syntax_tree, source, file_path));
                findings.extend(self.detect_file_access(&syntax_tree, source, file_path));
                findings.extend(self.detect_shell_commands(&syntax_tree, source, file_path));
                findings.extend(self.detect_process_spawn(&syntax_tree, source, file_path));
                findings.extend(self.detect_env_access(&syntax_tree, source, file_path));
                findings.extend(self.detect_dynamic_lib(&syntax_tree, source, file_path));
                findings.extend(self.detect_unsafe_blocks(&syntax_tree, source, file_path));
                findings.extend(self.detect_sensitive_paths(&syntax_tree, source, file_path));
                findings.extend(self.detect_obfuscation(&syntax_tree, source, file_path));
                findings.extend(self.detect_compiler_flags(source, file_path));
            }
            Err(e) => {
                tracing::warn!("Failed to parse {}: {}", file_path, e);
            }
        }

        findings
    }

    /// Detect network calls that could indicate data exfiltration or downloading malicious code.
    ///
    /// Looks for:
    /// - `use` statements importing network crates (reqwest, hyper, std::net, etc.)
    /// - Direct function/method calls to network APIs
    /// - Path expressions referencing network types
    fn detect_network_calls(&self, ast: &syn::File, source: &str, path: &str) -> Vec<Finding> {
        let mut visitor = NetworkCallVisitor::new(source, path);
        visitor.visit_file(ast);
        visitor.findings
    }

    /// Detect file system access that could indicate reading/writing outside expected paths.
    ///
    /// Looks for:
    /// - `use` statements importing std::fs, std::io, etc.
    /// - File::open, File::create, and other file operations
    /// - Path manipulation and file system queries
    fn detect_file_access(&self, ast: &syn::File, source: &str, path: &str) -> Vec<Finding> {
        let mut visitor = FileAccessVisitor::new(source, path);
        visitor.visit_file(ast);
        visitor.findings
    }

    fn detect_shell_commands(&self, _ast: &syn::File, _source: &str, _path: &str) -> Vec<Finding> {
        // TODO: Implement shell command detection
        Vec::new()
    }

    fn detect_process_spawn(&self, _ast: &syn::File, _source: &str, _path: &str) -> Vec<Finding> {
        // TODO: Implement process spawn detection
        Vec::new()
    }

    fn detect_env_access(&self, _ast: &syn::File, _source: &str, _path: &str) -> Vec<Finding> {
        // TODO: Implement env access detection
        Vec::new()
    }

    fn detect_dynamic_lib(&self, _ast: &syn::File, _source: &str, _path: &str) -> Vec<Finding> {
        // TODO: Implement dynamic lib detection
        Vec::new()
    }

    fn detect_unsafe_blocks(&self, _ast: &syn::File, _source: &str, _path: &str) -> Vec<Finding> {
        // TODO: Implement unsafe block detection
        Vec::new()
    }

    fn detect_sensitive_paths(&self, _ast: &syn::File, _source: &str, _path: &str) -> Vec<Finding> {
        // TODO: Implement sensitive path detection
        Vec::new()
    }

    fn detect_obfuscation(&self, _ast: &syn::File, _source: &str, _path: &str) -> Vec<Finding> {
        // TODO: Implement obfuscation detection
        Vec::new()
    }

    fn detect_compiler_flags(&self, _source: &str, _path: &str) -> Vec<Finding> {
        // TODO: Implement compiler flag detection
        Vec::new()
    }
}

impl Default for Detector {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Network Call Detection
// ============================================================================

/// Visitor that walks the AST looking for network-related patterns
struct NetworkCallVisitor<'a> {
    source: &'a str,
    file_path: &'a str,
    findings: Vec<Finding>,
}

impl<'a> NetworkCallVisitor<'a> {
    fn new(source: &'a str, file_path: &'a str) -> Self {
        Self {
            source,
            file_path,
            findings: Vec::new(),
        }
    }

    /// Check if a path segment matches any network pattern
    fn matches_network_pattern(path_str: &str) -> bool {
        for pattern in NETWORK_PATTERNS {
            if path_str.contains(pattern) {
                return true;
            }
        }
        false
    }

    /// Get the line number from a span
    fn get_line_number(&self, span: proc_macro2::Span) -> usize {
        span.start().line
    }

    /// Create a finding for a detected network pattern
    fn create_finding(&mut self, line: usize, pattern_found: &str, summary: &str) {
        let (context_before, snippet, context_after) =
            extract_snippet(self.source, line, line, 3);

        let finding = Finding::new(
            IssueType::Network,
            default_severity(IssueType::Network),
            self.file_path.to_string(),
            line,
            line,
            snippet,
            summary.to_string(),
        )
        .with_context(context_before, context_after)
        .with_details(serde_json::json!({
            "pattern": pattern_found,
            "detection_type": "network_call"
        }));

        self.findings.push(finding);
    }
}

impl<'a> Visit<'a> for NetworkCallVisitor<'a> {
    /// Check `use` statements for network crate imports
    fn visit_item_use(&mut self, node: &'a ItemUse) {
        let use_str = format_use_tree(&node.tree);
        if Self::matches_network_pattern(&use_str) {
            let line = self.get_line_number(node.use_token.span);
            let pattern = NETWORK_PATTERNS
                .iter()
                .find(|p| use_str.contains(*p))
                .unwrap_or(&"network");
            self.create_finding(
                line,
                pattern,
                &format!("Network crate import detected: {}", use_str),
            );
        }
        syn::visit::visit_item_use(self, node);
    }

    /// Check function calls for network-related functions
    fn visit_expr_call(&mut self, node: &'a ExprCall) {
        if let Expr::Path(ExprPath { path, .. }) = &*node.func {
            let path_str = format_path(path);
            if Self::matches_network_pattern(&path_str) {
                let line = self.get_line_number(path.segments.first().map_or_else(
                    || proc_macro2::Span::call_site(),
                    |s| s.ident.span(),
                ));
                let pattern = NETWORK_PATTERNS
                    .iter()
                    .find(|p| path_str.contains(*p))
                    .unwrap_or(&"network");
                self.create_finding(
                    line,
                    pattern,
                    &format!("Network function call detected: {}", path_str),
                );
            }
        }
        syn::visit::visit_expr_call(self, node);
    }

    /// Check method calls for network-related methods
    fn visit_expr_method_call(&mut self, node: &'a ExprMethodCall) {
        let method_name = node.method.to_string();
        // Common network method names that are suspicious in build scripts
        let suspicious_methods = ["connect", "bind", "send", "recv", "get", "post", "put", "delete"];

        // We look at the receiver to see if it's a network type
        if let Expr::Path(ExprPath { path, .. }) = &*node.receiver {
            let path_str = format_path(path);
            if Self::matches_network_pattern(&path_str) {
                let line = self.get_line_number(node.method.span());
                self.create_finding(
                    line,
                    &path_str,
                    &format!("Network method call detected: {}.{}", path_str, method_name),
                );
            }
        }

        // Also check for suspicious method names on any receiver
        // This catches cases like `client.get(url)` where client is from reqwest
        if suspicious_methods.contains(&method_name.as_str()) {
            // Walk up to check if this might be network-related based on context
            // For now, we're conservative and only flag when we're sure
        }

        syn::visit::visit_expr_method_call(self, node);
    }

    /// Check path expressions for network type references
    fn visit_expr_path(&mut self, node: &'a ExprPath) {
        let path_str = format_path(&node.path);
        if Self::matches_network_pattern(&path_str) {
            let line = self.get_line_number(
                node.path
                    .segments
                    .first()
                    .map_or_else(|| proc_macro2::Span::call_site(), |s| s.ident.span()),
            );
            let pattern = NETWORK_PATTERNS
                .iter()
                .find(|p| path_str.contains(*p))
                .unwrap_or(&"network");
            self.create_finding(
                line,
                pattern,
                &format!("Network type reference detected: {}", path_str),
            );
        }
        syn::visit::visit_expr_path(self, node);
    }
}

/// Format a syn::Path to a string for pattern matching
fn format_path(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|seg| seg.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

/// Format a UseTree to a string for pattern matching
fn format_use_tree(tree: &UseTree) -> String {
    match tree {
        UseTree::Path(path) => {
            format!("{}::{}", path.ident, format_use_tree(&path.tree))
        }
        UseTree::Name(name) => name.ident.to_string(),
        UseTree::Rename(rename) => rename.ident.to_string(),
        UseTree::Glob(_) => "*".to_string(),
        UseTree::Group(group) => group
            .items
            .iter()
            .map(format_use_tree)
            .collect::<Vec<_>>()
            .join(", "),
    }
}

// ============================================================================
// File Access Detection
// ============================================================================

/// Visitor that walks the AST looking for file system access patterns
struct FileAccessVisitor<'a> {
    source: &'a str,
    file_path: &'a str,
    findings: Vec<Finding>,
}

impl<'a> FileAccessVisitor<'a> {
    fn new(source: &'a str, file_path: &'a str) -> Self {
        Self {
            source,
            file_path,
            findings: Vec::new(),
        }
    }

    /// Check if a path segment matches any file access pattern
    fn matches_file_pattern(path_str: &str) -> bool {
        for pattern in FILE_ACCESS_PATTERNS {
            if path_str.contains(pattern) {
                return true;
            }
        }
        false
    }

    /// Get the line number from a span
    fn get_line_number(&self, span: proc_macro2::Span) -> usize {
        span.start().line
    }

    /// Create a finding for a detected file access pattern
    fn create_finding(&mut self, line: usize, pattern_found: &str, summary: &str) {
        let (context_before, snippet, context_after) =
            extract_snippet(self.source, line, line, 3);

        let finding = Finding::new(
            IssueType::FileAccess,
            default_severity(IssueType::FileAccess),
            self.file_path.to_string(),
            line,
            line,
            snippet,
            summary.to_string(),
        )
        .with_context(context_before, context_after)
        .with_details(serde_json::json!({
            "pattern": pattern_found,
            "detection_type": "file_access"
        }));

        self.findings.push(finding);
    }
}

impl<'a> Visit<'a> for FileAccessVisitor<'a> {
    /// Check `use` statements for file I/O crate imports
    fn visit_item_use(&mut self, node: &'a ItemUse) {
        let use_str = format_use_tree(&node.tree);
        if Self::matches_file_pattern(&use_str) {
            let line = self.get_line_number(node.use_token.span);
            let pattern = FILE_ACCESS_PATTERNS
                .iter()
                .find(|p| use_str.contains(*p))
                .unwrap_or(&"file_access");
            self.create_finding(
                line,
                pattern,
                &format!("File system import detected: {}", use_str),
            );
        }
        syn::visit::visit_item_use(self, node);
    }

    /// Check function calls for file-related functions
    fn visit_expr_call(&mut self, node: &'a ExprCall) {
        if let Expr::Path(ExprPath { path, .. }) = &*node.func {
            let path_str = format_path(path);
            if Self::matches_file_pattern(&path_str) {
                let line = self.get_line_number(path.segments.first().map_or_else(
                    || proc_macro2::Span::call_site(),
                    |s| s.ident.span(),
                ));
                let pattern = FILE_ACCESS_PATTERNS
                    .iter()
                    .find(|p| path_str.contains(*p))
                    .unwrap_or(&"file_access");
                self.create_finding(
                    line,
                    pattern,
                    &format!("File system function call detected: {}", path_str),
                );
            }
        }
        syn::visit::visit_expr_call(self, node);
    }

    /// Check method calls for file-related methods
    fn visit_expr_method_call(&mut self, node: &'a ExprMethodCall) {
        let method_name = node.method.to_string();

        // Check if the receiver is a file-related type
        if let Expr::Path(ExprPath { path, .. }) = &*node.receiver {
            let path_str = format_path(path);
            if Self::matches_file_pattern(&path_str) {
                let line = self.get_line_number(node.method.span());
                self.create_finding(
                    line,
                    &path_str,
                    &format!("File system method call detected: {}.{}", path_str, method_name),
                );
            }
        }

        // Also check for common file access method names
        if FILE_ACCESS_METHODS.contains(&method_name.as_str()) {
            let line = self.get_line_number(node.method.span());
            self.create_finding(
                line,
                &method_name,
                &format!("File access method detected: {}", method_name),
            );
        }

        syn::visit::visit_expr_method_call(self, node);
    }

    /// Check path expressions for file type references
    fn visit_expr_path(&mut self, node: &'a ExprPath) {
        let path_str = format_path(&node.path);
        if Self::matches_file_pattern(&path_str) {
            let line = self.get_line_number(
                node.path
                    .segments
                    .first()
                    .map_or_else(|| proc_macro2::Span::call_site(), |s| s.ident.span()),
            );
            let pattern = FILE_ACCESS_PATTERNS
                .iter()
                .find(|p| path_str.contains(*p))
                .unwrap_or(&"file_access");
            self.create_finding(
                line,
                pattern,
                &format!("File system type reference detected: {}", path_str),
            );
        }
        syn::visit::visit_expr_path(self, node);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that the detector detects `use reqwest` imports
    #[test]
    fn test_detect_reqwest_import() {
        let source = r#"
use reqwest;

fn main() {
    println!("Hello");
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let network_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::Network)
            .collect();

        assert!(!network_findings.is_empty(), "Should detect reqwest import");
        assert!(
            network_findings[0].summary.contains("reqwest"),
            "Summary should mention reqwest"
        );
    }

    /// Test that the detector detects `use hyper` imports
    #[test]
    fn test_detect_hyper_import() {
        let source = r#"
use hyper::Client;

fn main() {
    let client = Client::new();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let network_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::Network)
            .collect();

        assert!(!network_findings.is_empty(), "Should detect hyper import");
    }

    /// Test that the detector detects `std::net` imports
    #[test]
    fn test_detect_std_net_import() {
        let source = r#"
use std::net::TcpStream;

fn main() {
    let stream = TcpStream::connect("127.0.0.1:8080").unwrap();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let network_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::Network)
            .collect();

        assert!(!network_findings.is_empty(), "Should detect std::net import");
    }

    /// Test that the detector detects curl imports
    #[test]
    fn test_detect_curl_import() {
        let source = r#"
use curl::easy::Easy;

fn download() {
    let mut easy = Easy::new();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let network_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::Network)
            .collect();

        assert!(!network_findings.is_empty(), "Should detect curl import");
    }

    /// Test that network calls have Medium severity (as per spec)
    #[test]
    fn test_network_calls_have_medium_severity() {
        let source = r#"
use reqwest::blocking::get;

fn main() {
    let response = get("https://example.com").unwrap();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let network_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::Network)
            .collect();

        assert!(!network_findings.is_empty(), "Should detect network call");
        assert_eq!(
            network_findings[0].severity,
            sus_core::Severity::Medium,
            "Network calls should have Medium severity"
        );
    }

    /// Test that code context is extracted correctly
    #[test]
    fn test_context_extraction() {
        let source = r#"// Line 1
// Line 2
// Line 3
use reqwest;
// Line 5
// Line 6
// Line 7
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let network_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::Network)
            .collect();

        assert!(!network_findings.is_empty(), "Should detect reqwest import");
        let finding = &network_findings[0];

        // Context should include surrounding lines
        assert!(
            !finding.context_before.is_empty() || !finding.context_after.is_empty(),
            "Should have some context"
        );
    }

    /// Test detection of async networking (tokio::net)
    #[test]
    fn test_detect_tokio_net() {
        let source = r#"
use tokio::net::TcpListener;

async fn serve() {
    let listener = TcpListener::bind("0.0.0.0:8080").await.unwrap();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let network_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::Network)
            .collect();

        assert!(!network_findings.is_empty(), "Should detect tokio::net import");
    }

    /// Test that file access patterns are detected
    #[test]
    fn test_detect_file_access() {
        let source = r#"
use std::fs::File;

fn main() {
    let file = File::open("secret.txt").unwrap();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let file_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::FileAccess)
            .collect();

        assert!(!file_findings.is_empty(), "Should detect file access");
    }

    /// Test that file access has Medium severity
    #[test]
    fn test_file_access_has_medium_severity() {
        let source = r#"
use std::fs;

fn main() {
    fs::read_to_string("config.txt").unwrap();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let file_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::FileAccess)
            .collect();

        assert!(!file_findings.is_empty(), "Should detect file access");
        assert_eq!(
            file_findings[0].severity,
            sus_core::Severity::Medium,
            "File access should have Medium severity"
        );
    }
}
