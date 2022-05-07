#![no_main]

use libfuzzer_sys::fuzz_target;
use x509_cert::request::CertReq;

fuzz_target!(|input: &[u8]| {
    let _ = CertReq::try_from(input);
});
