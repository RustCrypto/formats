#![no_main]

use libfuzzer_sys::fuzz_target;
use x509_cert::request::CertReqInfo;

fuzz_target!(|input: &[u8]| {
    let _ = CertReqInfo::try_from(input);
});
