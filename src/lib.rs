extern crate libc;

#[macro_use]
extern crate lazy_static;

use std::ptr;
use std::mem;
use std::env;

use std::collections::HashMap;

use libc::{c_int, c_char, size_t};
use std::ffi::CString;
use std::ffi::CStr;

#[repr(C)] pub struct CertificateContext {
    private: [u8; 0]
}

#[link(name="certificate", kind="static")]
extern {
    pub fn init_cert_ctx();

    pub fn alloc_cert_cxt(data: * const u8, len: size_t) -> *mut CertificateContext;
    pub fn clean_cert_cxt(cxt: * mut CertificateContext);
    pub fn get_serial_number_cert_cxt(cxt: *mut CertificateContext, buf : * mut c_char) -> c_int;
    pub fn get_version_cert_cxt(cxt: *mut CertificateContext, version: * mut c_int);
    pub fn get_signature_algo(cxt: *mut CertificateContext, buf : * mut c_char, keylen : * mut c_int) -> c_int;
    pub fn get_publick_key_cxt(cxt: *mut CertificateContext, buf: * mut c_char, kbits: *mut c_int) -> c_int;
}

lazy_static! {
    static ref _doit: bool = unsafe {
        init_cert_ctx();
        true 
    };
}

#[derive(Debug)]
pub struct Certificate {
    cxt   :  * mut CertificateContext,
    inner :  Option<CertificateInner>
}

#[derive(Debug)]
pub struct CertificateInner {
    serial_number : String,
    version : i32,
    validity : Validity,

    subject : HashMap< String, Vec<String> >,
    issuer :  HashMap< String, Vec<String> >,
}

#[derive(Debug)]
pub struct Validity {
    not_before : String,
    not_after : String,
}

impl Certificate {
    pub fn new(v: Vec<u8>) -> Option<Self> {
        let data: * const u8 = v.as_ptr();
        let len: usize = v.len();

        let cxt = unsafe {
            let new_cxt = alloc_cert_cxt(data, len as size_t);
            if new_cxt.is_null() {
                return None;
            }
            new_cxt
        };
        let cert = Certificate {
            cxt : cxt,
            inner : None,
        };
        mem::forget(v);
        
        Some(cert)
    }

    pub fn cleanup(&mut self) {
        if self.cxt.is_null() {
            unsafe {
                clean_cert_cxt(self.cxt);
            }
        }
    }

    pub fn parse(&mut self) {
        unsafe {
            const SERIAL_NUM: usize = 1024;
            let mut buf: [i8; SERIAL_NUM] = mem::uninitialized();
            let ptr: * mut i8 = buf.as_mut_ptr();
            let res = get_serial_number_cert_cxt(self.cxt, ptr);
            if res != 0  {
                println!("Error: parse sereal number error");
                return;
            }
            let mut version: c_int = mem::uninitialized();
            get_version_cert_cxt(self.cxt, &mut version);

            let serial_number = CStr::from_ptr(ptr).to_string_lossy().into_owned();
            let version = version;
            // println!("sereal_num:{}  version:{}", self.serial_number, self.version);

        }
    }
}

impl Drop for Certificate {
    fn drop(&mut self) {
        self.cleanup();
    }
}
