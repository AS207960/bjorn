fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=migrations");
    tonic_build::compile_protos("proto/order.proto")?;
    Ok(())
}