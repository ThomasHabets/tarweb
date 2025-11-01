fn main() {
    let mut prost_build = prost_build::Config::new();
    prost_build
        .type_attribute(".", "#[derive(serde::Serialize,serde::Deserialize)]")
        .file_descriptor_set_path("descriptor.bin")
        .compile_protos(&["proto/sni_config.proto"], &["proto"])
        .unwrap();
}
