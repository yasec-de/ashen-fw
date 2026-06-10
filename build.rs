use micropb_gen::{Config, Generator};

fn main() {
    println!("cargo:rustc-link-arg-bins=--nmagic");
    println!("cargo:rustc-link-arg-bins=-Tlink.x");
    println!("cargo:rustc-link-arg-bins=-Tdefmt.x");
    println!("cargo:rustc-link-arg-bins=-Tkeystore.x");
    println!(
        "cargo:rustc-link-search={}",
        std::env::var("CARGO_MANIFEST_DIR").unwrap()
    );
    println!("cargo:rerun-if-changed=keystore.x");

    let out_dir = std::env::var("OUT_DIR").unwrap();

    let mut generator = Generator::new();
    generator.configure(
        ".",
        Config::new()
            .vec_type("alloc::vec::Vec<$T>")
            .string_type("alloc::string::String")
            .bytes_type("alloc::vec::Vec<u8>"),
    );
    generator
        .compile_protos(&["proto/device.proto"], format!("{out_dir}/device.rs"))
        .expect("failed to compile proto/device.proto");

    println!("cargo:rerun-if-changed=proto/device.proto");
}
