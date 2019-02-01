extern crate gcc;

fn main() {
    println!("cargo:rustc-link-search=native=/usr/local/opt/openssl/lib/");
    println!("cargo:rustc-link-lib=static=crypto");

    gcc::Build::new()
                 .file("src/c/certificate.c")
                 .flag("-I/usr/local/opt/openssl/include/")
                 .include("src")
                 .compile("libcertificate.a");
}
