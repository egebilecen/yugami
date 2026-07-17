use std::env;
use std::path::PathBuf;

fn main() {
    // Navigate up from packer's target build dir to the workspace target root.
    let mut stub_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    stub_path.pop(); // Pop "out".
    stub_path.pop(); // Pop the package build directory.
    stub_path.pop(); // Pop "build".
    
    // Now we are in "target/debug/" or "target/release/".
    // Push the stub name.
    #[cfg(target_os = "windows")]
    stub_path.push("stub.exe");

    #[cfg(not(target_os = "windows"))]
    stub_path.push("stub");

    // Pass the absolute stub path to packer's source code at compile time.
    println!("cargo:rustc-env=STUB_PATH={}", stub_path.display());
    
    // Instruct cargo to rerun this script if the stub binary changes.
    println!("cargo:rerun-if-changed={}", stub_path.display());
}
