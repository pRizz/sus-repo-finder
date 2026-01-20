//! Main detector implementation
//!
//! This module implements pattern detection for suspicious code in Rust build scripts
//! and proc-macro crates. It uses the `syn` crate for AST parsing and visitors.

use crate::patterns::{default_severity, extract_snippet, Finding};
use sus_core::IssueType;
use syn::visit::Visit;
use syn::{Expr, ExprCall, ExprLit, ExprMethodCall, ExprPath, ExprUnsafe, ItemUse, UseTree};

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

    /// Detect access to sensitive file paths that could indicate credential theft.
    ///
    /// Looks for:
    /// - String literals containing sensitive paths (~/.ssh, ~/.aws, /etc/passwd, etc.)
    /// - Path construction that references home directories plus sensitive subdirectories
    /// - Functions that access known credential files
    fn detect_sensitive_paths(&self, ast: &syn::File, source: &str, path: &str) -> Vec<Finding> {
        let mut visitor = SensitivePathVisitor::new(source, path);
        visitor.visit_file(ast);
        visitor.findings
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
// Unsafe Block Detection
// ============================================================================

/// Sensitive path patterns that could indicate credential theft or privacy violation.
/// Access to these paths from build scripts is highly suspicious.
const SENSITIVE_PATHS: &[&str] = &[
    // SSH keys and configuration
    ".ssh",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "authorized_keys",
    "known_hosts",
    // AWS credentials
    ".aws",
    "credentials",
    "aws_access_key",
    // GCP credentials
    ".gcloud",
    "application_default_credentials.json",
    "service_account.json",
    // Azure credentials
    ".azure",
    "accessTokens.json",
    // Docker credentials
    ".docker/config.json",
    // Kubernetes credentials
    ".kube/config",
    ".kube",
    // System files
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/hosts",
    // Git credentials
    ".gitconfig",
    ".git-credentials",
    ".netrc",
    // Browser data
    ".mozilla",
    ".chrome",
    ".chromium",
    "Local State",
    "Login Data",
    "Cookies",
    // Password managers
    ".gnupg",
    ".password-store",
    "Keychain",
    // NPM tokens
    ".npmrc",
    // Generic credential patterns
    "private_key",
    "privatekey",
    "secret",
    "token",
    "password",
    "passwd",
    "credential",
    // Shell history (could contain secrets)
    ".bash_history",
    ".zsh_history",
    ".history",
    // Environment files
    ".env",
    ".env.local",
    ".env.production",
    // IDE credentials
    ".vscode",
    ".idea",
];

/// Home directory expansion patterns
const HOME_EXPANSIONS: &[&str] = &[
    "~",
    "$HOME",
    "env::var(\"HOME\")",
    "env::var(\"USERPROFILE\")",
    "home_dir()",
    "dirs::home_dir",
    "BaseDirs",
];

/// Threshold for considering an unsafe block "large" (number of statements)
const LARGE_UNSAFE_BLOCK_THRESHOLD: usize = 5;

/// Raw pointer patterns that are particularly suspicious
const RAW_POINTER_PATTERNS: &[&str] = &[
    "*const",
    "*mut",
    "as_ptr",
    "as_mut_ptr",
    "offset",
    "add",
    "sub",
    "read",
    "write",
    "copy",
    "copy_nonoverlapping",
    "write_bytes",
    "read_unaligned",
    "write_unaligned",
    "read_volatile",
    "write_volatile",
    "drop_in_place",
    "transmute",
    "from_raw_parts",
    "from_raw_parts_mut",
    "slice_from_raw_parts",
    "slice_from_raw_parts_mut",
];

/// FFI-related patterns within unsafe blocks
const FFI_PATTERNS: &[&str] = &[
    "extern",
    "libc::",
    "winapi::",
    "ffi::",
    "c_void",
    "CStr",
    "CString",
];

/// Visitor that walks the AST looking for unsafe blocks
struct UnsafeBlockVisitor<'a> {
    source: &'a str,
    file_path: &'a str,
    findings: Vec<Finding>,
}

impl<'a> UnsafeBlockVisitor<'a> {
    fn new(source: &'a str, file_path: &'a str) -> Self {
        Self {
            source,
            file_path,
            findings: Vec::new(),
        }
    }

    /// Get the line number from a span
    fn get_line_number(&self, span: proc_macro2::Span) -> usize {
        span.start().line
    }

    /// Get the end line number from a span
    fn get_end_line_number(&self, span: proc_macro2::Span) -> usize {
        span.end().line
    }

    /// Count statements in an unsafe block
    fn count_statements(block: &syn::Block) -> usize {
        block.stmts.len()
    }

    /// Check if an expression contains raw pointer operations
    fn contains_raw_pointer_operations(source_snippet: &str) -> bool {
        for pattern in RAW_POINTER_PATTERNS {
            if source_snippet.contains(pattern) {
                return true;
            }
        }
        false
    }

    /// Check if an expression contains FFI patterns
    fn contains_ffi_patterns(source_snippet: &str) -> bool {
        for pattern in FFI_PATTERNS {
            if source_snippet.contains(pattern) {
                return true;
            }
        }
        false
    }

    /// Extract the source text for a given line range
    fn extract_source_lines(&self, start_line: usize, end_line: usize) -> String {
        let lines: Vec<&str> = self.source.lines().collect();
        let start_idx = start_line.saturating_sub(1);
        let end_idx = end_line.min(lines.len());
        lines[start_idx..end_idx].join("\n")
    }

    /// Create a finding for a detected unsafe block
    fn create_finding(
        &mut self,
        line_start: usize,
        line_end: usize,
        pattern_found: &str,
        summary: &str,
        is_suspicious: bool,
    ) {
        let (context_before, snippet, context_after) =
            extract_snippet(self.source, line_start, line_end, 3);

        // Large unsafe blocks or those with raw pointers get Medium severity
        // Generic unsafe blocks get Low severity (as per spec)
        let severity = if is_suspicious {
            sus_core::Severity::Medium
        } else {
            default_severity(IssueType::UnsafeBlock)
        };

        let finding = Finding::new(
            IssueType::UnsafeBlock,
            severity,
            self.file_path.to_string(),
            line_start,
            line_end,
            snippet,
            summary.to_string(),
        )
        .with_context(context_before, context_after)
        .with_details(serde_json::json!({
            "pattern": pattern_found,
            "detection_type": "unsafe_block",
            "is_suspicious": is_suspicious
        }));

        self.findings.push(finding);
    }
}

impl<'a> Visit<'a> for UnsafeBlockVisitor<'a> {
    /// Visit unsafe blocks in expressions
    fn visit_expr_unsafe(&mut self, node: &'a ExprUnsafe) {
        let start_line = self.get_line_number(node.unsafe_token.span);
        let end_line = self.get_end_line_number(
            node.block
                .brace_token
                .span
                .close(),
        );

        let stmt_count = Self::count_statements(&node.block);
        let source_snippet = self.extract_source_lines(start_line, end_line);

        let has_raw_pointers = Self::contains_raw_pointer_operations(&source_snippet);
        let has_ffi = Self::contains_ffi_patterns(&source_snippet);
        let is_large = stmt_count >= LARGE_UNSAFE_BLOCK_THRESHOLD;

        // Determine what makes this unsafe block suspicious
        let mut reasons = Vec::new();
        if is_large {
            reasons.push(format!("large block ({} statements)", stmt_count));
        }
        if has_raw_pointers {
            reasons.push("raw pointer manipulation".to_string());
        }
        if has_ffi {
            reasons.push("FFI calls".to_string());
        }

        let is_suspicious = is_large || has_raw_pointers || has_ffi;

        let summary = if reasons.is_empty() {
            "Unsafe block detected".to_string()
        } else {
            format!("Unsafe block detected: {}", reasons.join(", "))
        };

        let pattern = if has_raw_pointers {
            "raw_pointer"
        } else if has_ffi {
            "ffi"
        } else if is_large {
            "large_block"
        } else {
            "unsafe_block"
        };

        self.create_finding(start_line, end_line, pattern, &summary, is_suspicious);

        // Continue visiting child nodes
        syn::visit::visit_expr_unsafe(self, node);
    }

    /// Also check for unsafe functions
    fn visit_item_fn(&mut self, node: &'a syn::ItemFn) {
        if node.sig.unsafety.is_some() {
            let start_line = self.get_line_number(node.sig.fn_token.span);
            let end_line = if let Some(block) = node.block.stmts.last() {
                // Get the end of the last statement
                self.source
                    .lines()
                    .enumerate()
                    .filter(|(_, _line)| true)
                    .count()
                    .min(start_line + 20) // Limit to reasonable size
            } else {
                start_line
            };

            let source_snippet = self.extract_source_lines(start_line, end_line.min(start_line + 20));
            let has_raw_pointers = Self::contains_raw_pointer_operations(&source_snippet);
            let has_ffi = Self::contains_ffi_patterns(&source_snippet);

            let is_suspicious = has_raw_pointers || has_ffi;

            let summary = format!(
                "Unsafe function declared: {}{}",
                node.sig.ident,
                if has_raw_pointers {
                    " (contains raw pointer operations)"
                } else if has_ffi {
                    " (contains FFI calls)"
                } else {
                    ""
                }
            );

            self.create_finding(
                start_line,
                start_line,
                "unsafe_fn",
                &summary,
                is_suspicious,
            );
        }

        // Continue visiting the function body
        syn::visit::visit_item_fn(self, node);
    }
}

// ============================================================================
// Sensitive Path Detection
// ============================================================================

/// Visitor that walks the AST looking for access to sensitive file paths.
/// This detects potential credential theft or privacy violations.
struct SensitivePathVisitor<'a> {
    source: &'a str,
    file_path: &'a str,
    findings: Vec<Finding>,
}

impl<'a> SensitivePathVisitor<'a> {
    fn new(source: &'a str, file_path: &'a str) -> Self {
        Self {
            source,
            file_path,
            findings: Vec::new(),
        }
    }

    /// Check if a string contains a sensitive path pattern
    fn contains_sensitive_path(s: &str) -> Option<&'static str> {
        let s_lower = s.to_lowercase();
        for pattern in SENSITIVE_PATHS {
            // Check for the pattern as a path component or substring
            if s_lower.contains(&pattern.to_lowercase()) {
                return Some(pattern);
            }
        }
        None
    }

    /// Check if a string contains home directory expansion patterns
    fn contains_home_expansion(s: &str) -> bool {
        for pattern in HOME_EXPANSIONS {
            if s.contains(pattern) {
                return true;
            }
        }
        false
    }

    /// Determine if a path access is particularly dangerous
    fn is_highly_sensitive(path: &str) -> bool {
        let path_lower = path.to_lowercase();
        // These paths are most commonly targeted for credential theft
        path_lower.contains(".ssh")
            || path_lower.contains("id_rsa")
            || path_lower.contains("id_ed25519")
            || path_lower.contains(".aws")
            || path_lower.contains("/etc/passwd")
            || path_lower.contains("/etc/shadow")
            || path_lower.contains(".gnupg")
            || path_lower.contains("private_key")
            || path_lower.contains("secret")
    }

    /// Get the line number from a span
    fn get_line_number(&self, span: proc_macro2::Span) -> usize {
        span.start().line
    }

    /// Create a finding for a detected sensitive path access
    fn create_finding(&mut self, line: usize, path_detected: &str, summary: &str) {
        let (context_before, snippet, context_after) =
            extract_snippet(self.source, line, line, 3);

        let finding = Finding::new(
            IssueType::SensitivePath,
            default_severity(IssueType::SensitivePath), // High severity
            self.file_path.to_string(),
            line,
            line,
            snippet,
            summary.to_string(),
        )
        .with_context(context_before, context_after)
        .with_details(serde_json::json!({
            "pattern": path_detected,
            "detection_type": "sensitive_path",
            "is_highly_sensitive": Self::is_highly_sensitive(path_detected)
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

impl<'a> Visit<'a> for SensitivePathVisitor<'a> {
    /// Check literal expressions for sensitive paths
    fn visit_expr_lit(&mut self, node: &'a ExprLit) {
        if let Some(path_str) = Self::extract_string_literal(&node.lit) {
            if let Some(pattern) = Self::contains_sensitive_path(&path_str) {
                let line = self.get_line_number(node.lit.span());
                let has_home = Self::contains_home_expansion(&path_str);

                let summary = if has_home {
                    format!(
                        "Sensitive path access detected (home directory): \"{}\" (matches pattern: {})",
                        path_str, pattern
                    )
                } else {
                    format!(
                        "Sensitive path access detected: \"{}\" (matches pattern: {})",
                        path_str, pattern
                    )
                };

                self.create_finding(line, &path_str, &summary);
            }
        }
        syn::visit::visit_expr_lit(self, node);
    }

    /// Check function calls that might be constructing paths
    fn visit_expr_call(&mut self, node: &'a ExprCall) {
        // Check if this is a Path::new() or PathBuf::from() call with sensitive argument
        if let Expr::Path(ExprPath { path, .. }) = &*node.func {
            let path_str = format_path(path);

            // Check for path construction functions
            if path_str.contains("Path::new")
                || path_str.contains("PathBuf::from")
                || path_str.contains("PathBuf::new")
            {
                // Check the arguments for sensitive paths
                for arg in &node.args {
                    if let Expr::Lit(ExprLit { lit, .. }) = arg {
                        if let Some(arg_str) = Self::extract_string_literal(lit) {
                            if let Some(pattern) = Self::contains_sensitive_path(&arg_str) {
                                let line = self.get_line_number(
                                    path.segments
                                        .first()
                                        .map_or_else(|| proc_macro2::Span::call_site(), |s| s.ident.span()),
                                );
                                self.create_finding(
                                    line,
                                    &arg_str,
                                    &format!(
                                        "Path construction to sensitive location: {}(\"{}\")",
                                        path_str, arg_str
                                    ),
                                );
                            }
                        }
                    }
                }
            }

            // Check for home directory functions
            if path_str.contains("home_dir")
                || path_str.contains("dirs::home_dir")
                || path_str.contains("BaseDirs")
                || path_str.contains("UserDirs")
            {
                let line = self.get_line_number(
                    path.segments
                        .first()
                        .map_or_else(|| proc_macro2::Span::call_site(), |s| s.ident.span()),
                );
                // This is just home directory access, not necessarily sensitive
                // We flag it with lower priority - it becomes concerning when combined with sensitive paths
                // Check if this is used in a chain with push() to a sensitive path
            }
        }
        syn::visit::visit_expr_call(self, node);
    }

    /// Check method calls for path operations that might access sensitive locations
    fn visit_expr_method_call(&mut self, node: &'a ExprMethodCall) {
        let method_name = node.method.to_string();

        // Check for .push() and .join() which are used to construct paths
        if method_name == "push" || method_name == "join" {
            for arg in &node.args {
                if let Expr::Lit(ExprLit { lit, .. }) = arg {
                    if let Some(arg_str) = Self::extract_string_literal(lit) {
                        if let Some(pattern) = Self::contains_sensitive_path(&arg_str) {
                            let line = self.get_line_number(node.method.span());
                            self.create_finding(
                                line,
                                &arg_str,
                                &format!(
                                    "Path {}() to sensitive location: \"{}\" (matches pattern: {})",
                                    method_name, arg_str, pattern
                                ),
                            );
                        }
                    }
                }
            }
        }

        // Check for read operations on paths
        if method_name == "read_to_string"
            || method_name == "read"
            || method_name == "read_dir"
        {
            // Check if the receiver or earlier parts of the chain contain sensitive paths
            // This is handled by the literal check
        }

        syn::visit::visit_expr_method_call(self, node);
    }

    /// Check macro calls for sensitive paths (e.g., include_str!, include_bytes!)
    fn visit_macro(&mut self, node: &'a syn::Macro) {
        // Get the macro path
        let macro_path = format_path(&node.path);

        // Check for include macros which read files at compile time
        if macro_path.contains("include_str")
            || macro_path.contains("include_bytes")
            || macro_path.contains("include")
        {
            // The tokens inside the macro might contain a path string
            let tokens_str = node.tokens.to_string();
            if let Some(pattern) = Self::contains_sensitive_path(&tokens_str) {
                let line = self.get_line_number(
                    node.path
                        .segments
                        .first()
                        .map_or_else(|| proc_macro2::Span::call_site(), |s| s.ident.span()),
                );
                self.create_finding(
                    line,
                    &tokens_str,
                    &format!(
                        "Macro accessing sensitive path: {}!({}) (matches pattern: {})",
                        macro_path, tokens_str, pattern
                    ),
                );
            }
        }

        syn::visit::visit_macro(self, node);
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

    // ========================================================================
    // Unsafe Block Detection Tests
    // ========================================================================

    /// Test detection of basic unsafe block
    #[test]
    fn test_detect_basic_unsafe_block() {
        let source = r#"
fn main() {
    unsafe {
        let x = 5;
    }
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let unsafe_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::UnsafeBlock)
            .collect();

        assert!(!unsafe_findings.is_empty(), "Should detect unsafe block");
    }

    /// Test that basic unsafe blocks have Low severity (as per spec)
    #[test]
    fn test_basic_unsafe_has_low_severity() {
        let source = r#"
fn main() {
    unsafe {
        let x = 5;
    }
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let unsafe_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::UnsafeBlock)
            .collect();

        assert!(!unsafe_findings.is_empty(), "Should detect unsafe block");
        assert_eq!(
            unsafe_findings[0].severity,
            sus_core::Severity::Low,
            "Basic unsafe block should have Low severity"
        );
    }

    /// Test detection of large unsafe block (many statements)
    #[test]
    fn test_detect_large_unsafe_block() {
        let source = r#"
fn main() {
    unsafe {
        let a = 1;
        let b = 2;
        let c = 3;
        let d = 4;
        let e = 5;
        let f = 6;
    }
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let unsafe_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::UnsafeBlock)
            .collect();

        assert!(!unsafe_findings.is_empty(), "Should detect large unsafe block");
        // Large unsafe blocks should be flagged as suspicious
        assert!(
            unsafe_findings[0].summary.contains("large block") ||
            unsafe_findings[0].summary.contains("statements"),
            "Should mention large block in summary"
        );
    }

    /// Test detection of raw pointer manipulation
    #[test]
    fn test_detect_raw_pointer_manipulation() {
        let source = r#"
fn main() {
    let ptr: *const i32 = std::ptr::null();
    unsafe {
        let val = *ptr;
    }
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let unsafe_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::UnsafeBlock)
            .collect();

        assert!(!unsafe_findings.is_empty(), "Should detect unsafe block with raw pointer");
    }

    /// Test detection of transmute (particularly dangerous)
    #[test]
    fn test_detect_transmute() {
        let source = r#"
fn dangerous() {
    unsafe {
        let x: i32 = std::mem::transmute(1.0f32);
    }
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let unsafe_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::UnsafeBlock)
            .collect();

        assert!(!unsafe_findings.is_empty(), "Should detect transmute in unsafe block");
        // Transmute should be flagged as raw pointer manipulation
        assert!(
            unsafe_findings.iter().any(|f| f.summary.contains("raw pointer")),
            "Should flag transmute as raw pointer manipulation"
        );
    }

    /// Test detection of unsafe function
    #[test]
    fn test_detect_unsafe_function() {
        let source = r#"
unsafe fn dangerous_function() {
    let x = 5;
}

fn main() {}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let unsafe_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::UnsafeBlock)
            .collect();

        assert!(!unsafe_findings.is_empty(), "Should detect unsafe function");
        assert!(
            unsafe_findings.iter().any(|f| f.summary.contains("Unsafe function")),
            "Should mention unsafe function in summary"
        );
    }

    /// Test detection of FFI patterns within unsafe
    #[test]
    fn test_detect_ffi_in_unsafe() {
        let source = r#"
use std::ffi::CStr;

fn main() {
    unsafe {
        let c_str: *const libc::c_char = std::ptr::null();
        CStr::from_ptr(c_str);
    }
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let unsafe_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::UnsafeBlock)
            .collect();

        assert!(!unsafe_findings.is_empty(), "Should detect FFI in unsafe block");
    }

    /// Test that raw pointer manipulation has Medium severity (elevated from Low)
    #[test]
    fn test_raw_pointer_has_medium_severity() {
        let source = r#"
fn main() {
    let ptr: *const i32 = std::ptr::null();
    unsafe {
        let val = ptr.read();
    }
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let unsafe_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::UnsafeBlock)
            .filter(|f| f.summary.contains("raw pointer"))
            .collect();

        assert!(!unsafe_findings.is_empty(), "Should detect raw pointer operations");
        assert_eq!(
            unsafe_findings[0].severity,
            sus_core::Severity::Medium,
            "Raw pointer manipulation should have Medium severity"
        );
    }

    /// Test detection of from_raw_parts (memory manipulation)
    #[test]
    fn test_detect_from_raw_parts() {
        let source = r#"
fn main() {
    let data = vec![1, 2, 3];
    let ptr = data.as_ptr();
    unsafe {
        let slice = std::slice::from_raw_parts(ptr, 3);
    }
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let unsafe_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::UnsafeBlock)
            .collect();

        assert!(!unsafe_findings.is_empty(), "Should detect from_raw_parts in unsafe");
        assert!(
            unsafe_findings.iter().any(|f| f.summary.contains("raw pointer")),
            "Should flag from_raw_parts as raw pointer manipulation"
        );
    }

    /// Test detection of pointer offset operations
    #[test]
    fn test_detect_pointer_offset() {
        let source = r#"
fn main() {
    let arr = [1, 2, 3, 4, 5];
    let ptr = arr.as_ptr();
    unsafe {
        let elem = *ptr.offset(2);
    }
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let unsafe_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::UnsafeBlock)
            .collect();

        assert!(!unsafe_findings.is_empty(), "Should detect pointer offset in unsafe");
        assert!(
            unsafe_findings.iter().any(|f| f.summary.contains("raw pointer")),
            "Should flag offset as raw pointer manipulation"
        );
    }

    /// Test context extraction for unsafe blocks
    #[test]
    fn test_unsafe_block_context_extraction() {
        let source = r#"// Line 1
// Line 2
// Line 3
fn main() {
    unsafe {
        let x = 5;
    }
}
// Line 9
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let unsafe_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::UnsafeBlock)
            .collect();

        assert!(!unsafe_findings.is_empty(), "Should detect unsafe block");
        let finding = &unsafe_findings[0];

        // Context should include surrounding lines
        assert!(
            !finding.context_before.is_empty() || !finding.context_after.is_empty(),
            "Should have some context"
        );
    }

    /// Test multiple unsafe blocks in same file
    #[test]
    fn test_multiple_unsafe_blocks() {
        let source = r#"
fn first() {
    unsafe {
        let a = 1;
    }
}

fn second() {
    unsafe {
        let b = 2;
    }
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let unsafe_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::UnsafeBlock)
            .collect();

        assert!(
            unsafe_findings.len() >= 2,
            "Should detect multiple unsafe blocks, found {}",
            unsafe_findings.len()
        );
    }

    // ========================================================================
    // Sensitive Path Detection Tests
    // ========================================================================

    /// Test detection of ~/.ssh access
    #[test]
    fn test_detect_ssh_directory_access() {
        let source = r#"
use std::fs;

fn steal_keys() {
    let keys = fs::read_to_string("~/.ssh/id_rsa").unwrap();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let sensitive_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::SensitivePath)
            .collect();

        assert!(!sensitive_findings.is_empty(), "Should detect ~/.ssh access");
        assert!(
            sensitive_findings.iter().any(|f| f.summary.contains(".ssh") || f.summary.contains("id_rsa")),
            "Summary should mention .ssh or id_rsa"
        );
    }

    /// Test that sensitive path access has High severity
    #[test]
    fn test_sensitive_path_has_high_severity() {
        let source = r#"
fn main() {
    let path = "/etc/passwd";
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let sensitive_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::SensitivePath)
            .collect();

        assert!(!sensitive_findings.is_empty(), "Should detect /etc/passwd access");
        assert_eq!(
            sensitive_findings[0].severity,
            sus_core::Severity::High,
            "Sensitive path access should have High severity"
        );
    }

    /// Test detection of AWS credentials path
    #[test]
    fn test_detect_aws_credentials_path() {
        let source = r#"
use std::fs;

fn steal_aws() {
    let creds = fs::read_to_string("~/.aws/credentials").unwrap();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let sensitive_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::SensitivePath)
            .collect();

        assert!(!sensitive_findings.is_empty(), "Should detect ~/.aws access");
        assert!(
            sensitive_findings.iter().any(|f| f.summary.contains(".aws") || f.summary.contains("credentials")),
            "Summary should mention .aws or credentials"
        );
    }

    /// Test detection of /etc/shadow (highly sensitive)
    #[test]
    fn test_detect_etc_shadow() {
        let source = r#"
fn main() {
    let shadow = std::fs::read_to_string("/etc/shadow");
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let sensitive_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::SensitivePath)
            .collect();

        assert!(!sensitive_findings.is_empty(), "Should detect /etc/shadow access");
    }

    /// Test detection of Path::new() with sensitive path
    #[test]
    fn test_detect_path_new_sensitive() {
        let source = r#"
use std::path::Path;

fn main() {
    let path = Path::new("~/.gnupg/private-keys-v1.d");
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let sensitive_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::SensitivePath)
            .collect();

        assert!(!sensitive_findings.is_empty(), "Should detect Path::new with sensitive path");
    }

    /// Test detection of path.join() with sensitive path
    #[test]
    fn test_detect_path_join_sensitive() {
        let source = r#"
use std::path::PathBuf;

fn main() {
    let home = PathBuf::from("/home/user");
    let ssh = home.join(".ssh");
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let sensitive_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::SensitivePath)
            .collect();

        assert!(!sensitive_findings.is_empty(), "Should detect path.join() with .ssh");
    }

    /// Test detection of .env file access
    #[test]
    fn test_detect_env_file_access() {
        let source = r#"
fn main() {
    let env_contents = std::fs::read_to_string(".env").unwrap();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let sensitive_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::SensitivePath)
            .collect();

        assert!(!sensitive_findings.is_empty(), "Should detect .env file access");
    }

    /// Test detection of browser data access
    #[test]
    fn test_detect_browser_data_access() {
        let source = r#"
fn steal_cookies() {
    let cookies = std::fs::read("~/.mozilla/firefox/cookies.sqlite");
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let sensitive_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::SensitivePath)
            .collect();

        assert!(!sensitive_findings.is_empty(), "Should detect browser data access");
    }

    /// Test detection of shell history access
    #[test]
    fn test_detect_shell_history_access() {
        let source = r#"
fn exfiltrate_history() {
    let history = std::fs::read_to_string("~/.bash_history").unwrap();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let sensitive_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::SensitivePath)
            .collect();

        assert!(!sensitive_findings.is_empty(), "Should detect .bash_history access");
    }

    /// Test detection of Kubernetes config access
    #[test]
    fn test_detect_kube_config_access() {
        let source = r#"
fn steal_kube_config() {
    let config = std::fs::read_to_string("~/.kube/config").unwrap();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let sensitive_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::SensitivePath)
            .collect();

        assert!(!sensitive_findings.is_empty(), "Should detect .kube/config access");
    }

    /// Test detection of docker config access
    #[test]
    fn test_detect_docker_config_access() {
        let source = r#"
fn steal_docker_creds() {
    let config = std::fs::read_to_string("~/.docker/config.json").unwrap();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let sensitive_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::SensitivePath)
            .collect();

        assert!(!sensitive_findings.is_empty(), "Should detect .docker/config.json access");
    }

    /// Test context extraction for sensitive path findings
    #[test]
    fn test_sensitive_path_context_extraction() {
        let source = r#"// Line 1
// Line 2
// Line 3
fn steal() {
    let key = "~/.ssh/id_rsa";
}
// Line 7
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let sensitive_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::SensitivePath)
            .collect();

        assert!(!sensitive_findings.is_empty(), "Should detect sensitive path");
        let finding = &sensitive_findings[0];

        // Context should include surrounding lines
        assert!(
            !finding.context_before.is_empty() || !finding.context_after.is_empty(),
            "Should have some context"
        );
    }

    /// Test that non-sensitive paths are not flagged
    #[test]
    fn test_non_sensitive_path_not_flagged() {
        let source = r#"
fn main() {
    let path = "/usr/local/bin/myapp";
    let data = std::fs::read("/tmp/data.txt");
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let sensitive_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::SensitivePath)
            .collect();

        // These paths are not in the sensitive list
        assert!(
            sensitive_findings.is_empty(),
            "Non-sensitive paths should not be flagged, found: {:?}",
            sensitive_findings.iter().map(|f| &f.summary).collect::<Vec<_>>()
        );
    }

    /// Test detection of private key patterns in paths
    #[test]
    fn test_detect_private_key_path() {
        let source = r#"
fn steal_keys() {
    let key = std::fs::read("/app/private_key.pem");
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let sensitive_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::SensitivePath)
            .collect();

        assert!(!sensitive_findings.is_empty(), "Should detect private_key in path");
    }

    /// Test detection of NPM tokens
    #[test]
    fn test_detect_npmrc_access() {
        let source = r#"
fn steal_npm_token() {
    let npmrc = std::fs::read_to_string("~/.npmrc").unwrap();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let sensitive_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::SensitivePath)
            .collect();

        assert!(!sensitive_findings.is_empty(), "Should detect .npmrc access");
    }

    /// Test detection of git credentials
    #[test]
    fn test_detect_git_credentials_access() {
        let source = r#"
fn steal_git_creds() {
    let creds = std::fs::read_to_string("~/.git-credentials").unwrap();
}
"#;
        let detector = Detector::new();
        let findings = detector.analyze(source, "build.rs");

        let sensitive_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.issue_type == IssueType::SensitivePath)
            .collect();

        assert!(!sensitive_findings.is_empty(), "Should detect .git-credentials access");
    }
}
