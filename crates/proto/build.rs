fn main() {
    let proto = "proto/tether/v1/tether.proto";

    // Rerun only on the schema itself. Without this, prost regenerates on every
    // build, and a build that does unnecessary work is a build whose output people
    // stop trusting to be deterministic (HR-12.5).
    println!("cargo:rerun-if-changed={proto}");

    prost_build::compile_protos(&[proto], &["proto"])
        .expect("protoc failed; is protoc on PATH? see requirements.txt");
}
