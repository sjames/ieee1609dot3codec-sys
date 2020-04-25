use bindgen;
use cc;
use std::env;
use std::fs::{self};
use std::path::{Path, PathBuf};
use std::process::Command;

/// return a tuple of lists. The first entry contains the list of .c files and the
/// second entry is the list of headers in the specified directory.
fn find_generated_sources_and_headers(out_dir: &Path) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut sources = Vec::new();
    let mut headers = Vec::new();

    if out_dir.is_dir() {
        for entry in fs::read_dir(out_dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_file() {
                if let Some(extension) = path.extension() {
                    match extension.to_str().unwrap() {
                        "c" => sources.push(PathBuf::from(path)),
                        "h" => headers.push(PathBuf::from(path)),
                        _ => {}
                    }
                }
            }
        }
    }
    (sources, headers)
}

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Generate the codec source files from the ASN.1 specification.
    Command::new("asn1c")
        .args(&[
            "asn1/1609dot3all.asn",
            "-D",
            out_dir.to_str().unwrap(),
            "-fcompound-names",
            "-no-gen-example",
        ])
        .status()
        .unwrap();

    let (sources, headers) = find_generated_sources_and_headers(&out_dir);

    let mut cc_builder = cc::Build::new();
    cc_builder.include(&out_dir.to_str().unwrap());

    for source in sources {
        cc_builder.file(&source);
    }

    cc_builder.flag("-Wno-missing-field-initializers");
    cc_builder.flag("-Wno-missing-braces");
    cc_builder.flag("-Wno-unused-parameter");
    cc_builder.flag("-Wno-unused-const-variable");
    cc_builder.compile("libasn1codec");

    // Generate Bindings
    let mut builder = bindgen::Builder::default()
        .clang_arg(format!("-I{}", &out_dir.to_str().unwrap()))
        .header("sys/types.h")
        .header("stdio.h");

    for header in headers {
        builder = builder.header(String::from(header.to_str().unwrap()));
    }
    let bindings = builder.generate().expect("Unable to generate bindings");
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
