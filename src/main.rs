extern crate x509_parser;

use std::fs::{File};
use std::io::Read;

use x509_parser::Certificate;

fn main() -> std::io::Result<()> {
    // let path = env::current_dir()?;
    // println!("{:?}", path.display() );

    let mut cert_cxt;
    {
        let mut f = File::open("./src/cert/mycert.der")?;
        let mut cert = vec![];
        f.read_to_end(&mut cert)?;

        cert_cxt = Certificate::new(cert).unwrap();
        println!("{:?}", cert_cxt);
    }
    cert_cxt.parse();

    /*
    let oval = unsafe {
        let val = get_opaque_val(ptr);
        val as i32
    };
    println!("val = {}", oval);
    unsafe {
        clean_opaque(ptr);
    };
    */

    Ok(())
}