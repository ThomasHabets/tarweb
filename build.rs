fn main() {
    let mut prost_build = prost_build::Config::new();
    let out_dir = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());

    prost_build
        .type_attribute(".", "#[derive(serde::Serialize,serde::Deserialize)]")
        .file_descriptor_set_path(out_dir.join("descriptor.bin"))
        .compile_protos(&["proto/sni_config.proto"], &["proto"])
        .unwrap();
}
