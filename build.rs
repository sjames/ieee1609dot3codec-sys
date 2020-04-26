use bindgen;
use cc;
use std::env;
use std::fs::File;
use std::fs::{self};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use syn::{ForeignItem, Item, Type};

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

    // parse the bindings. Return a string with the trait implementation for ASN1GenType
    // appended to the string.
    let bindings_with_trait_impl = generate_traits(bindings.to_string()).unwrap();

    let mut f =
        File::create(out_dir.join("bindings.rs")).expect("Unable to create file bindings.rs");
    f.write_all(bindings_with_trait_impl.as_bytes())
        .expect("Unable to write bindings");
}

fn find_descriptors(bindings: &String) -> Vec<String> {
    let mut ids = Vec::<String>::new();

    let n = "asn_DEF_".len();
    let syntax = syn::parse_file(&bindings).expect("Unable to parse generated binding");

    for item in &syntax.items {
        match item {
            Item::ForeignMod(item) => {
                for it in &item.items {
                    match it {
                        ForeignItem::Static(item) => match &*item.ty {
                            Type::Path(path) => {
                                if let Some(ident) = path.path.get_ident() {
                                    if ident == "asn_TYPE_descriptor_t" {
                                        let name = item.ident.to_string();
                                        if is_struct(&name[n..], &syntax) {
                                            ids.push(name);
                                        }
                                    }
                                }
                            }
                            _ => {}
                        },
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    ids
}

fn is_struct(desc_type_name: &str, parsed_file: &syn::File) -> bool {
    for item in &parsed_file.items {
        match item {
            Item::Struct(item) => {
                if desc_type_name == item.ident.to_string() {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn generate_trait_impl(typename: &str) -> String {
    let template = r###"
    impl ASN1GenType for {TYPENAME}{
        unsafe fn get_descriptor() -> &'static asn_TYPE_descriptor_t {
            &asn_DEF_{TYPENAME}
        }
    }
"###;
    template.replace("{TYPENAME}", typename)
}

fn generate_traits(mut bindings: String) -> Option<String> {
    let asn1_descriptors = find_descriptors(&bindings);
    let n = "asn_DEF_".len();
    for gen_type in asn1_descriptors {
        let trait_impl = generate_trait_impl(&gen_type[n..]);
        bindings.push_str(&trait_impl);
    }
    Some(bindings)
}
