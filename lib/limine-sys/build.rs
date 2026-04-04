use std::env;
use std::path::PathBuf;

fn main() {
    let header = "../../limine/limine-protocol/include/limine.h";
    println!("cargo:rerun-if-changed={}", header);

    let bindings = bindgen::Builder::default()
        .header(header)
        .use_core()
        .derive_default(true)
        .clang_arg("-ffreestanding")
        .clang_arg("-nostdlib")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
