//! Main detector implementation
//!
//! This module implements pattern detection for suspicious code in Rust build scripts
//! and proc-macro crates. It uses the `syn` crate for AST parsing and visitors.

use crate::patterns::{default_severity, extract_snippet, Finding};
use sus_core::IssueType;
use syn::visit::Visit;
use syn::{Expr, ExprCall, ExprMethodCall, ExprPath, ExprUnsafe, ItemUse, UseTree};

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

/// Shell command and process execution patterns to detect.
/// These indicate potential arbitrary command execution in build scripts.
const SHELL_COMMAND_PATTERNS: &[&str] = &[
    // Standard library process module
    "std::process",
    "Command",
    // Common shell names that might be invoked
    "bash",
    "sh",
    "cmd",
    "powershell",
    "pwsh",
    "zsh",
    "fish",
    // Direct executable paths
    "/bin/sh",
    "/bin/bash",
    "/usr/bin/env",
];

/// Shell invocation arguments that are particularly suspicious
/// (indicate shell interpretation of commands)
const SUSPICIOUS_SHELL_ARGS: &[&str] = &[
    "-c",    // Execute command string
    "/C",    // Windows cmd.exe execute
    "-e",    // Execute expression
    "eval",  // Shell eval
    "exec",  // Shell exec
];

/// Environment variable access patterns to detect.
/// These indicate build scripts reading environment variables which could
/// be exfiltrating sensitive data or making build behavior unpredictable.
const ENV_ACCESS_PATTERNS: &[&str] = &[
    // Standard library env module
    "std::env",
    "env::var",
    "env::var_os",
    "env::vars",
    "env::vars_os",
    "env::set_var",
    "env::remove_var",
];

/// Sensitive environment variable names that are particularly concerning
/// when accessed from build scripts. Accessing these elevates severity to High.
const SENSITIVE_ENV_VARS: &[&str] = &[
    // Authentication and credentials
    "AWS_ACCESS_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITLAB_TOKEN",
    "NPM_TOKEN",
    "DOCKER_PASSWORD",
    "DOCKER_AUTH",
    "API_KEY",
    "SECRET_KEY",
    "PRIVATE_KEY",
    "PASSWORD",
    "PASSWD",
    "CREDENTIALS",
    "AUTH_TOKEN",
    "ACCESS_TOKEN",
    "BEARER_TOKEN",
    // SSH and GPG
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "GPG_TTY",
    "GPG_AGENT_INFO",
    // Cloud providers
    "AZURE_CLIENT_SECRET",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GCP_SERVICE_ACCOUNT",
    // Database credentials
    "DATABASE_URL",
    "DATABASE_PASSWORD",
    "DB_PASSWORD",
    "POSTGRES_PASSWORD",
    "MYSQL_PASSWORD",
    "REDIS_PASSWORD",
    "MONGODB_URI",
    // CI/CD secrets
    "CI_JOB_TOKEN",
    "CIRCLE_TOKEN",
    "TRAVIS_TOKEN",
    "JENKINS_TOKEN",
    // Home directory access
    "HOME",
    "USERPROFILE",
];

/// Environment access methods that indicate reading/writing env vars
const ENV_ACCESS_METHODS: &[&str] = &[
    "var",
    "var_os",
    "vars",
    "vars_os",
    "set_var",
    "remove_var",
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

    /// Detect shell command execution that could run arbitrary code.
    ///
    /// Looks for:
    /// - `use` statements importing std::process or Command
    /// - Command::new() calls, especially with shell names (bash, sh, cmd)
    /// - Method calls like .arg(), .args(), .spawn(), .output()
    fn detect_shell_commands(&self, ast: &syn::File, source: &str, path: &str) -> Vec<Finding> {
        let mut visitor = ShellCommandVisitor::new(source, path);
        visitor.visit_file(ast);
        visitor.findings
    }

    fn detect_process_spawn(&self, _ast: &syn::File, _source: &str, _path: &str) -> Vec<Finding> {
        // TODO: Implement process spawn detection
        Vec::new()
    }

    /// Detect environment variable access that could leak sensitive data.
    ///
    /// Looks for:
    /// - `use` statements importing std::env
    /// - env::var(), env::var_os() function calls
    /// - Access to sensitive environment variables (AWS keys, tokens, etc.)
    fn detect_env_access(&self, ast: &syn::File, source: &str, path: &str) -> Vec<Finding> {
        let mut visitor = EnvAccessVisitor::new(source, path);
        visitor.visit_file(ast);
        visitor.findings
    }

    fn detect_dynamic_lib(&self, _ast: &syn::File, _source: &str, _path: &str) -> Vec<Finding> {
        // TODO: Implement dynamic lib detection
        Vec::new()
    }

    /// Detect unsafe blocks that could hide malicious behavior.
    ///
    /// Looks for:
    /// - Large unsafe blocks (many statements indicate complex unsafe code)
    /// - Raw pointer manipulation (deref, offset, as *const, as *mut)
    /// - FFI calls within unsafe blocks
    fn detect_unsafe_blocks(&self, ast: &syn::File, source: &str, path: &str) -> Vec<Finding> {
        let mut visitor = UnsafeBlockVisitor::new(source, path);
        visitor.visit_file(ast);
        visitor.findings
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
// Shell Command Detection
// ============================================================================

/// Visitor that walks the AST looking for shell command execution patterns
struct ShellCommandVisitor<'a> {
    source: &'a str,
    file_path: &'a str,
    findings: Vec<Finding>,
}

impl<'a> ShellCommandVisitor<'a> {
    fn new(source: &'a str, file_path: &'a str) -> Self {
        Self {
            source,
            file_path,
            findings: Vec::new(),
        }
    }

    /// Check if a path segment matches any shell command pattern
    fn matches_shell_pattern(path_str: &str) -> bool {
        for pattern in SHELL_COMMAND_PATTERNS {
            if path_str.contains(pattern) {
                return true;
            }
        }
        false
    }

    /// Check if a string literal is a shell name
    fn is_shell_name(s: &str) -> bool {
        let shell_names = ["bash", "sh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "zsh", "fish"];
        shell_names.contains(&s) || s.starts_with("/bin/") || s.starts_with("/usr/bin/") || s.contains("\\cmd") || s.contains("\\powershell")
    }

    /// Get the line number from a span
    fn get_line_number(&self, span: proc_macro2::Span) -> usize {
        span.start().line
    }

    /// Create a finding for a detected shell command pattern
    fn create_finding(&mut self, line: usize, pattern_found: &str, summary: &str) {
        let (context_before, snippet, context_after) =
            extract_snippet(self.source, line, line, 3);

        let finding = Finding::new(
            IssueType::ShellCommand,
            default_severity(IssueType::ShellCommand),
            self.file_path.to_string(),
            line,
            line,
            snippet,
            summary.to_string(),
        )
        .with_context(context_before, context_after)
        .with_details(serde_json::json!({
            "pattern": pattern_found,
            "detection_type": "shell_command"
        }));

        self.findings.push(finding);
    }

    /// Extract string literal value from a syn::Lit
    fn extract_string_literal(lit: &syn::Lit) -> Option<String> {
        if let syn::Lit::Str(lit_str) = lit {
            Some(lit_str.value())
        } else {
            None
        }
    }
}

impl<'a> Visit<'a> for ShellCommandVisitor<'a> {
    /// Check `use` statements for process/command imports
    fn visit_item_use(&mut self, node: &'a ItemUse) {
        let use_str = format_use_tree(&node.tree);
        if Self::matches_shell_pattern(&use_str) {
            let line = self.get_line_number(node.use_token.span);
            let pattern = SHELL_COMMAND_PATTERNS
                .iter()
                .find(|p| use_str.contains(*p))
                .unwrap_or(&"shell_command");
            self.create_finding(
                line,
                pattern,
                &format!("Process/command import detected: {}", use_str),
            );
        }
        syn::visit::visit_item_use(self, node);
    }

    /// Check function calls for Command::new() and similar
    fn visit_expr_call(&mut self, node: &'a ExprCall) {
        if let Expr::Path(ExprPath { path, .. }) = &*node.func {
            let path_str = format_path(path);

            // Detect Command::new() specifically
            if path_str == "Command::new" || path_str.ends_with("::Command::new") {
                let line = self.get_line_number(path.segments.first().map_or_else(
                    || proc_macro2::Span::call_site(),
                    |s| s.ident.span(),
                ));

                // Check if the argument is a shell name
                let shell_name = node.args.first().and_then(|arg| {
                    if let Expr::Lit(expr_lit) = arg {
                        Self::extract_string_literal(&expr_lit.lit)
                    } else {
                        None
                    }
                });

                let summary = if let Some(ref name) = shell_name {
                    if Self::is_shell_name(name) {
                        format!("Shell command execution detected: Command::new(\"{}\")", name)
                    } else {
                        format!("Command execution detected: Command::new(\"{}\")", name)
                    }
                } else {
                    "Command execution detected: Command::new()".to_string()
                };

                self.create_finding(line, "Command::new", &summary);
            } else if Self::matches_shell_pattern(&path_str) {
                let line = self.get_line_number(path.segments.first().map_or_else(
                    || proc_macro2::Span::call_site(),
                    |s| s.ident.span(),
                ));
                let pattern = SHELL_COMMAND_PATTERNS
                    .iter()
                    .find(|p| path_str.contains(*p))
                    .unwrap_or(&"shell_command");
                self.create_finding(
                    line,
                    pattern,
                    &format!("Shell command function call detected: {}", path_str),
                );
            }
        }
        syn::visit::visit_expr_call(self, node);
    }

    /// Check method calls for command-related methods
    fn visit_expr_method_call(&mut self, node: &'a ExprMethodCall) {
        let method_name = node.method.to_string();

        // Check for Command method chain calls: .arg(), .args(), .spawn(), .output(), .status()
        let command_methods = ["arg", "args", "spawn", "output", "status", "current_dir", "env", "envs"];

        if command_methods.contains(&method_name.as_str()) {
            // For .arg() calls, check if the argument is suspicious
            if method_name == "arg" || method_name == "args" {
                if let Some(first_arg) = node.args.first() {
                    if let Expr::Lit(expr_lit) = first_arg {
                        if let Some(arg_value) = Self::extract_string_literal(&expr_lit.lit) {
                            // Check for suspicious shell arguments like "-c"
                            if SUSPICIOUS_SHELL_ARGS.contains(&arg_value.as_str()) {
                                let line = self.get_line_number(node.method.span());
                                self.create_finding(
                                    line,
                                    &arg_value,
                                    &format!("Suspicious shell argument detected: .{}(\"{}\")", method_name, arg_value),
                                );
                            }
                        }
                    }
                }
            }

            // Check if receiver might be a Command
            if let Expr::Path(ExprPath { path, .. }) = &*node.receiver {
                let path_str = format_path(path);
                if path_str.contains("Command") || path_str.contains("cmd") {
                    let line = self.get_line_number(node.method.span());
                    self.create_finding(
                        line,
                        &method_name,
                        &format!("Command method call detected: {}.{}()", path_str, method_name),
                    );
                }
            }
        }

        syn::visit::visit_expr_method_call(self, node);
    }

    /// Check path expressions for Command type references
    fn visit_expr_path(&mut self, node: &'a ExprPath) {
        let path_str = format_path(&node.path);
        if Self::matches_shell_pattern(&path_str) {
            let line = self.get_line_number(
                node.path
                    .segments
                    .first()
                    .map_or_else(|| proc_macro2::Span::call_site(), |s| s.ident.span()),
            );
            let pattern = SHELL_COMMAND_PATTERNS
                .iter()
                .find(|p| path_str.contains(*p))
                .unwrap_or(&"shell_command");
            self.create_finding(
                line,
                pattern,
                &format!("Shell command type reference detected: {}", path_str),
            );
        }
        syn::visit::visit_expr_path(self, node);
    }
}

// ============================================================================
// Environment Variable Access Detection
// ============================================================================

/// Visitor that walks the AST looking for environment variable access patterns.
/// This detects potential data exfiltration through environment variables or
/// build scripts that access sensitive credentials.
struct EnvAccessVisitor<'a> {
    source: &'a str,
    file_path: &'a str,
    findings: Vec<Finding>,
}

impl<'a> EnvAccessVisitor<'a> {
    fn new(source: &'a str, file_path: &'a str) -> Self {
        Self {
            source,
            file_path,
            findings: Vec::new(),
        }
    }

    /// Check if a path segment matches any env access pattern
    fn matches_env_pattern(path_str: &str) -> bool {
        for pattern in ENV_ACCESS_PATTERNS {
            if path_str.contains(pattern) {
                return true;
            }
        }
        false
    }

    /// Check if an env var name is sensitive (credentials, secrets, etc.)
    fn is_sensitive_env_var(name: &str) -> bool {
        let name_upper = name.to_uppercase();
        for sensitive in SENSITIVE_ENV_VARS {
            if name_upper.contains(sensitive) {
                return true;
            }
        }
        // Also check for common patterns
        name_upper.contains("SECRET")
            || name_upper.contains("TOKEN")
            || name_upper.contains("KEY")
            || name_upper.contains("PASSWORD")
            || name_upper.contains("CREDENTIAL")
            || name_upper.contains("PRIVATE")
    }

    /// Get the line number from a span
    fn get_line_number(&self, span: proc_macro2::Span) -> usize {
        span.start().line
    }

    /// Create a finding for a detected env access pattern
    fn create_finding(
        &mut self,
        line: usize,
        pattern_found: &str,
        summary: &str,
        is_sensitive: bool,
    ) {
        let (context_before, snippet, context_after) =
            extract_snippet(self.source, line, line, 3);

        // Sensitive env var access is High severity, general env access is Low
        let severity = if is_sensitive {
            sus_core::Severity::High
        } else {
            default_severity(IssueType::EnvAccess)
        };

        let finding = Finding::new(
            IssueType::EnvAccess,
            severity,
            self.file_path.to_string(),
            line,
            line,
            snippet,
            summary.to_string(),
        )
        .with_context(context_before, context_after)
        .with_details(serde_json::json!({
            "pattern": pattern_found,
            "detection_type": "env_access",
            "is_sensitive": is_sensitive
        }));

        self.findings.push(finding);
    }

    /// Extract string literal value from a syn::Lit
    fn extract_string_literal(lit: &syn::Lit) -> Option<String> {
        if let syn::Lit::Str(lit_str) = lit {
            Some(lit_str.value())
        } else {
            None
        }
    }
}

impl<'a> Visit<'a> for EnvAccessVisitor<'a> {
    /// Check `use` statements for env module imports
    fn visit_item_use(&mut self, node: &'a ItemUse) {
        let use_str = format_use_tree(&node.tree);
        if Self::matches_env_pattern(&use_str) {
            let line = self.get_line_number(node.use_token.span);
            let pattern = ENV_ACCESS_PATTERNS
                .iter()
                .find(|p| use_str.contains(*p))
                .unwrap_or(&"env_access");
            self.create_finding(
                line,
                pattern,
                &format!("Environment module import detected: {}", use_str),
                false, // import itself isn't sensitive
            );
        }
        syn::visit::visit_item_use(self, node);
    }

    /// Check function calls for env::var() and similar
    fn visit_expr_call(&mut self, node: &'a ExprCall) {
        if let Expr::Path(ExprPath { path, .. }) = &*node.func {
            let path_str = format_path(path);

            // Detect env::var(), env::var_os(), etc.
            if Self::matches_env_pattern(&path_str) {
                let line = self.get_line_number(path.segments.first().map_or_else(
                    || proc_macro2::Span::call_site(),
                    |s| s.ident.span(),
                ));

                // Check if accessing a sensitive env var
                let env_var_name = node.args.first().and_then(|arg| {
                    if let Expr::Lit(expr_lit) = arg {
                        Self::extract_string_literal(&expr_lit.lit)
                    } else {
                        None
                    }
                });

                let (summary, is_sensitive) = if let Some(ref name) = env_var_name {
                    let sensitive = Self::is_sensitive_env_var(name);
                    let summary = if sensitive {
                        format!(
                            "Sensitive environment variable access detected: {}(\"{}\")",
                            path_str, name
                        )
                    } else {
                        format!("Environment variable access detected: {}(\"{}\")", path_str, name)
                    };
                    (summary, sensitive)
                } else {
                    (
                        format!("Environment variable access detected: {}", path_str),
                        false,
                    )
                };

                self.create_finding(line, &path_str, &summary, is_sensitive);
            }
        }
        syn::visit::visit_expr_call(self, node);
    }

    /// Check method calls for env-related methods
    fn visit_expr_method_call(&mut self, node: &'a ExprMethodCall) {
        let method_name = node.method.to_string();

        // Check for env access method names
        if ENV_ACCESS_METHODS.contains(&method_name.as_str()) {
            // Check if receiver is env-related
            if let Expr::Path(ExprPath { path, .. }) = &*node.receiver {
                let path_str = format_path(path);
                if path_str.contains("env") || Self::matches_env_pattern(&path_str) {
                    let line = self.get_line_number(node.method.span());

                    // Check if accessing a sensitive env var
                    let env_var_name = node.args.first().and_then(|arg| {
                        if let Expr::Lit(expr_lit) = arg {
                            Self::extract_string_literal(&expr_lit.lit)
                        } else {
                            None
                        }
                    });

                    let (summary, is_sensitive) = if let Some(ref name) = env_var_name {
                        let sensitive = Self::is_sensitive_env_var(name);
                        let summary = if sensitive {
                            format!(
                                "Sensitive environment variable access detected: {}.{}(\"{}\")",
                                path_str, method_name, name
                            )
                        } else {
                            format!(
                                "Environment variable method call detected: {}.{}(\"{}\")",
                                path_str, method_name, name
                            )
                        };
                        (summary, sensitive)
                    } else {
                        (
                            format!(
                                "Environment variable method call detected: {}.{}()",
                                path_str, method_name
                            ),
                            false,
                        )
                    };

                    self.create_finding(line, &method_name, &summary, is_sensitive);
                }
            }
        }

        syn::visit::visit_expr_method_call(self, node);
    }

    /// Check path expressions for env type references
    fn visit_expr_path(&mut self, node: &'a ExprPath) {
        let path_str = format_path(&node.path);
        if Self::matches_env_pattern(&path_str) {
            let line = self.get_line_number(
                node.path
                    .segments
                    .first()
                    .map_or_else(|| proc_macro2::Span::call_site(), |s| s.ident.span()),
            );
            let pattern = ENV_ACCESS_PATTERNS
                .iter()
                .find(|p| path_str.contains(*p))
                .unwrap_or(&"env_access");
            self.create_finding(
                line,
                pattern,
                &format!("Environment module reference detected: {}", path_str),
                false,
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

    /// Test detection of std::io imports
    #[test]
    fn test_detect_std_io_import() {
        let source = r#"
use std::io::Read;
use std::io::Write;

fn main() {}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let file_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::FileAccess)
            .collect();

        assert!(!file_findings.is_empty(), "Should detect std::io import");
    }

    /// Test detection of file operation methods
    #[test]
    fn test_detect_file_method_calls() {
        let source = r#"
fn main() {
    let data = some_file.read_to_string();
    another_file.write_all(b"data");
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let file_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::FileAccess)
            .collect();

        // Should detect read_to_string and write_all method calls
        assert!(
            file_findings.len() >= 2,
            "Should detect file method calls, found {}",
            file_findings.len()
        );
    }

    /// Test detection of directory operations
    #[test]
    fn test_detect_directory_operations() {
        let source = r#"
use std::fs;

fn setup() {
    fs::create_dir_all("output/nested").unwrap();
    fs::remove_dir_all("temp").unwrap();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let file_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::FileAccess)
            .collect();

        assert!(!file_findings.is_empty(), "Should detect directory operations");
    }

    /// Test detection of tokio async file operations
    #[test]
    fn test_detect_tokio_fs() {
        let source = r#"
use tokio::fs;

async fn async_file_op() {
    fs::read_to_string("file.txt").await.unwrap();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let file_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::FileAccess)
            .collect();

        assert!(!file_findings.is_empty(), "Should detect tokio::fs import");
    }

    // ========================================================================
    // Shell Command Detection Tests
    // ========================================================================

    /// Test detection of Command::new("bash") - the primary test case
    #[test]
    fn test_detect_command_new_bash() {
        let source = r#"
use std::process::Command;

fn main() {
    Command::new("bash").arg("-c").arg("echo hello").spawn();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let shell_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::ShellCommand)
            .collect();

        assert!(!shell_findings.is_empty(), "Should detect Command::new(\"bash\")");
        assert!(
            shell_findings.iter().any(|f| f.summary.contains("bash")),
            "Summary should mention bash"
        );
    }

    /// Test that shell commands have Medium severity
    #[test]
    fn test_shell_commands_have_medium_severity() {
        let source = r#"
use std::process::Command;

fn main() {
    Command::new("sh").spawn();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let shell_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::ShellCommand)
            .collect();

        assert!(!shell_findings.is_empty(), "Should detect shell command");
        assert_eq!(
            shell_findings[0].severity,
            sus_core::Severity::Medium,
            "Shell commands should have Medium severity"
        );
    }

    /// Test detection of std::process::Command import
    #[test]
    fn test_detect_process_command_import() {
        let source = r#"
use std::process::Command;

fn main() {}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let shell_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::ShellCommand)
            .collect();

        assert!(!shell_findings.is_empty(), "Should detect std::process::Command import");
    }

    /// Test detection of different shell names
    #[test]
    fn test_detect_various_shells() {
        // Test sh
        let source_sh = r#"
use std::process::Command;
fn main() { Command::new("sh").spawn(); }
"#;
        let detector = Detector::new();
        let findings_sh = detector.analyze(source_sh, "build.rs");
        let shell_findings_sh: Vec<_> = findings_sh
            .iter()
            .filter(|f| f.issue_type == IssueType::ShellCommand)
            .collect();
        assert!(!shell_findings_sh.is_empty(), "Should detect sh");

        // Test cmd (Windows)
        let source_cmd = r#"
use std::process::Command;
fn main() { Command::new("cmd").spawn(); }
"#;
        let findings_cmd = detector.analyze(source_cmd, "build.rs");
        let shell_findings_cmd: Vec<_> = findings_cmd
            .iter()
            .filter(|f| f.issue_type == IssueType::ShellCommand)
            .collect();
        assert!(!shell_findings_cmd.is_empty(), "Should detect cmd");

        // Test powershell
        let source_ps = r#"
use std::process::Command;
fn main() { Command::new("powershell").spawn(); }
"#;
        let findings_ps = detector.analyze(source_ps, "build.rs");
        let shell_findings_ps: Vec<_> = findings_ps
            .iter()
            .filter(|f| f.issue_type == IssueType::ShellCommand)
            .collect();
        assert!(!shell_findings_ps.is_empty(), "Should detect powershell");
    }

    /// Test detection of suspicious shell arguments like -c
    #[test]
    fn test_detect_suspicious_shell_args() {
        let source = r#"
use std::process::Command;

fn main() {
    Command::new("bash")
        .arg("-c")
        .arg("rm -rf /")
        .spawn();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let shell_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::ShellCommand)
            .collect();

        assert!(!shell_findings.is_empty(), "Should detect shell command with -c arg");
        // Should have multiple findings: import, Command::new, and the -c argument
        assert!(
            shell_findings.iter().any(|f| f.summary.contains("-c")),
            "Should flag the -c argument as suspicious"
        );
    }

    /// Test detection of Command with absolute path
    #[test]
    fn test_detect_absolute_path_shell() {
        let source = r#"
use std::process::Command;

fn main() {
    Command::new("/bin/sh").spawn();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let shell_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::ShellCommand)
            .collect();

        assert!(!shell_findings.is_empty(), "Should detect /bin/sh command");
        assert!(
            shell_findings.iter().any(|f| f.summary.contains("/bin/sh")),
            "Summary should mention /bin/sh"
        );
    }

    /// Test that non-shell commands are still detected but not flagged as shell
    #[test]
    fn test_detect_non_shell_command() {
        let source = r#"
use std::process::Command;

fn main() {
    Command::new("cargo").arg("build").spawn();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let shell_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::ShellCommand)
            .collect();

        // Should still detect Command::new but summary should say "Command execution" not "Shell command execution"
        assert!(!shell_findings.is_empty(), "Should detect Command::new");
        let cargo_finding = shell_findings.iter().find(|f| f.summary.contains("cargo"));
        assert!(cargo_finding.is_some(), "Should find cargo command");
        assert!(
            cargo_finding.unwrap().summary.contains("Command execution"),
            "Non-shell commands should say 'Command execution' not 'Shell command execution'"
        );
    }

    /// Test that context is extracted for shell commands
    #[test]
    fn test_shell_command_context_extraction() {
        let source = r#"// Line 1
// Line 2
// Line 3
use std::process::Command;
// Line 5
// Line 6
// Line 7
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let shell_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::ShellCommand)
            .collect();

        assert!(!shell_findings.is_empty(), "Should detect Command import");
        let finding = &shell_findings[0];

        // Context should include surrounding lines
        assert!(
            !finding.context_before.is_empty() || !finding.context_after.is_empty(),
            "Should have some context"
        );
    }

    /// Test detection using /usr/bin/env
    #[test]
    fn test_detect_usr_bin_env() {
        let source = r#"
use std::process::Command;

fn main() {
    Command::new("/usr/bin/env").arg("python").arg("script.py").spawn();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let shell_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::ShellCommand)
            .collect();

        assert!(!shell_findings.is_empty(), "Should detect /usr/bin/env command");
    }

    // ========================================================================
    // Environment Variable Access Detection Tests
    // ========================================================================

    /// Test detection of std::env import
    #[test]
    fn test_detect_std_env_import() {
        let source = r#"
use std::env;

fn main() {
    println!("Hello");
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let env_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::EnvAccess)
            .collect();

        assert!(!env_findings.is_empty(), "Should detect std::env import");
        assert!(
            env_findings[0].summary.contains("std::env"),
            "Summary should mention std::env"
        );
    }

    /// Test detection of env::var() function call
    #[test]
    fn test_detect_env_var_call() {
        let source = r#"
use std::env;

fn main() {
    let value = env::var("MY_VAR").unwrap();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let env_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::EnvAccess)
            .collect();

        assert!(!env_findings.is_empty(), "Should detect env::var() call");
        assert!(
            env_findings.iter().any(|f| f.summary.contains("MY_VAR")),
            "Summary should mention the variable name"
        );
    }

    /// Test that general env access has Low severity (as per spec)
    #[test]
    fn test_env_access_has_low_severity() {
        let source = r#"
use std::env;

fn main() {
    let path = env::var("PATH").unwrap();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let env_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::EnvAccess)
            .filter(|f| f.summary.contains("PATH"))
            .collect();

        assert!(!env_findings.is_empty(), "Should detect env access");
        assert_eq!(
            env_findings[0].severity,
            sus_core::Severity::Low,
            "General env access should have Low severity"
        );
    }

    /// Test that sensitive env var access has High severity
    #[test]
    fn test_sensitive_env_var_has_high_severity() {
        let source = r#"
use std::env;

fn main() {
    let token = env::var("GITHUB_TOKEN").unwrap();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let env_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::EnvAccess)
            .filter(|f| f.summary.contains("GITHUB_TOKEN"))
            .collect();

        assert!(!env_findings.is_empty(), "Should detect GITHUB_TOKEN access");
        assert_eq!(
            env_findings[0].severity,
            sus_core::Severity::High,
            "Sensitive env var access should have High severity"
        );
    }

    /// Test detection of AWS credentials access
    #[test]
    fn test_detect_aws_credentials_access() {
        let source = r#"
use std::env;

fn exfiltrate() {
    let key = env::var("AWS_SECRET_ACCESS_KEY").unwrap();
    let id = env::var("AWS_ACCESS_KEY_ID").unwrap();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let env_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::EnvAccess)
            .filter(|f| f.summary.contains("AWS"))
            .collect();

        assert!(
            env_findings.len() >= 2,
            "Should detect both AWS credential accesses"
        );
        assert!(
            env_findings.iter().all(|f| f.severity == sus_core::Severity::High),
            "All AWS credential accesses should be High severity"
        );
    }

    /// Test detection of various sensitive env vars
    #[test]
    fn test_detect_various_sensitive_vars() {
        // Test DATABASE_URL
        let source_db = r#"
use std::env;
fn main() { let db = env::var("DATABASE_URL").unwrap(); }
"#;
        let detector = Detector::new();
        let findings_db = detector.analyze(source_db, "build.rs");
        let env_findings_db: Vec<_> = findings_db
            .iter()
            .filter(|f| f.issue_type == IssueType::EnvAccess && f.summary.contains("DATABASE_URL"))
            .collect();
        assert!(
            !env_findings_db.is_empty() && env_findings_db[0].severity == sus_core::Severity::High,
            "DATABASE_URL should be High severity"
        );

        // Test SSH_AUTH_SOCK
        let source_ssh = r#"
use std::env;
fn main() { let sock = env::var("SSH_AUTH_SOCK").unwrap(); }
"#;
        let findings_ssh = detector.analyze(source_ssh, "build.rs");
        let env_findings_ssh: Vec<_> = findings_ssh
            .iter()
            .filter(|f| f.issue_type == IssueType::EnvAccess && f.summary.contains("SSH_AUTH_SOCK"))
            .collect();
        assert!(
            !env_findings_ssh.is_empty() && env_findings_ssh[0].severity == sus_core::Severity::High,
            "SSH_AUTH_SOCK should be High severity"
        );

        // Test NPM_TOKEN
        let source_npm = r#"
use std::env;
fn main() { let token = env::var("NPM_TOKEN").unwrap(); }
"#;
        let findings_npm = detector.analyze(source_npm, "build.rs");
        let env_findings_npm: Vec<_> = findings_npm
            .iter()
            .filter(|f| f.issue_type == IssueType::EnvAccess && f.summary.contains("NPM_TOKEN"))
            .collect();
        assert!(
            !env_findings_npm.is_empty() && env_findings_npm[0].severity == sus_core::Severity::High,
            "NPM_TOKEN should be High severity"
        );
    }

    /// Test that context is extracted for env access
    #[test]
    fn test_env_access_context_extraction() {
        let source = r#"// Line 1
// Line 2
// Line 3
use std::env;
// Line 5
// Line 6
// Line 7
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let env_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::EnvAccess)
            .collect();

        assert!(!env_findings.is_empty(), "Should detect env import");
        let finding = &env_findings[0];

        // Context should include surrounding lines
        assert!(
            !finding.context_before.is_empty() || !finding.context_after.is_empty(),
            "Should have some context"
        );
    }

    /// Test detection of env::var_os() function
    #[test]
    fn test_detect_env_var_os() {
        let source = r#"
use std::env;

fn main() {
    let value = env::var_os("MY_VAR");
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let env_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::EnvAccess)
            .filter(|f| f.summary.contains("MY_VAR"))
            .collect();

        assert!(!env_findings.is_empty(), "Should detect env::var_os() call");
    }

    /// Test detection of env::vars() to enumerate all environment variables
    #[test]
    fn test_detect_env_vars_enumeration() {
        let source = r#"
use std::env;

fn enumerate_env() {
    for (key, value) in env::vars() {
        println!("{}: {}", key, value);
    }
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let env_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::EnvAccess)
            .collect();

        assert!(!env_findings.is_empty(), "Should detect env::vars() call");
    }

    /// Test detection of env::set_var() which can poison environment
    #[test]
    fn test_detect_env_set_var() {
        let source = r#"
use std::env;

fn poison() {
    env::set_var("PATH", "/malicious/bin");
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let env_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::EnvAccess)
            .filter(|f| f.summary.contains("set_var") || f.summary.contains("PATH"))
            .collect();

        assert!(!env_findings.is_empty(), "Should detect env::set_var() call");
    }

    /// Test that sensitive keyword patterns are detected (e.g., MY_API_KEY)
    #[test]
    fn test_detect_sensitive_keyword_patterns() {
        let source = r#"
use std::env;

fn main() {
    let key = env::var("MY_API_KEY").unwrap();
    let secret = env::var("SUPER_SECRET_VALUE").unwrap();
    let pass = env::var("DB_PASSWORD").unwrap();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let env_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::EnvAccess)
            .filter(|f| f.severity == sus_core::Severity::High)
            .collect();

        // Should detect all three as sensitive because they contain KEY, SECRET, PASSWORD
        assert!(
            env_findings.len() >= 3,
            "Should detect all sensitive keyword patterns as High severity, found {}",
            env_findings.len()
        );
    }
}
