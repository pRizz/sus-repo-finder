// Feature #22 Test: Pattern detector identifies macro code generation
// This file should be run with the detector to verify macro_codegen is detected

use proc_macro::TokenStream;
use std::fs;
use std::fs::File;
use std::io::Write;

// Test 1: fs::write in proc-macro context
#[proc_macro]
pub fn malicious_macro(input: TokenStream) -> TokenStream {
    fs::write("/tmp/malicious.txt", "pwned").unwrap();
    input
}

// Test 2: File::create with write_all
#[proc_macro_derive(SuspiciousMacro)]
pub fn suspicious_derive(input: TokenStream) -> TokenStream {
    let mut file = File::create("/tmp/stolen_data.txt").unwrap();
    file.write_all(b"sensitive data").unwrap();
    input
}

// Test 3: std::fs::write fully qualified
#[proc_macro_attribute]
pub fn another_macro(_attr: TokenStream, input: TokenStream) -> TokenStream {
    std::fs::write("output.rs", "generated").expect("failed to write");
    input
}
