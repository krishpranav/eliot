// build.rs runs BEFORE the main compilation.
// Tonic-build calls protoc, generates .rs files in OUT_DIR,
// and the include_proto! macro in main.rs pulls them in at compile time.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        // Keep field names as-is (snake_case) from the proto
        .build_server(true)   // we are the gRPC server
        .build_client(false)  // we do NOT call other gRPC services from Rust
        .compile(
            &["../proto/nethawk.proto"],  // path to proto file
            &["../proto"],               // include dirs for imports
        )?;
    Ok(())
}
