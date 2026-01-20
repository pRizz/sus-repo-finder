//! Simple CLI test for the detector
//! Run with: rustc --edition 2021 -L target/debug/deps test_detector_cli.rs -o test_detector_cli && ./test_detector_cli

fn main() {
    // Test code with file access patterns
    let test_code = r#"
use std::fs::File;
use std::io::Read;

fn main() {
    let mut file = File::open("secret.txt").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    std::fs::remove_file("secret.txt").unwrap();
}
"#;

    println!("Test code:\n{}", test_code);
    println!("\nThis code should trigger FileAccess findings.");
    println!("\nPatterns to detect:");
    println!("  - use std::fs::File (import)");
    println!("  - use std::io::Read (import)");
    println!("  - File::open (method call)");
    println!("  - read_to_string (method call)");
    println!("  - std::fs::remove_file (function call)");
}
