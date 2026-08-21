//! Test re-encoding of all sample requests and responses.
//!
//! Files that are not OCSP messages — certificates, keys, CRLs — are skipped by failing to decode
//! as either.

use der::{Decode, Encode};
use std::fs;
use x509_ocsp::{OcspRequest, OcspResponse};

const REQUESTS: usize = 9;
const RESPONSES: usize = 16;

#[test]
fn every_message_reencodes_to_itself() {
    let mut requests = 0usize;
    let mut responses = 0usize;
    let mut skipped = 0usize;

    let mut names = fs::read_dir("tests/examples")
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect::<Vec<String>>();
    names.sort();

    for name in &names {
        let bytes = fs::read(format!("tests/examples/{name}")).unwrap();

        if let Ok(response) = OcspResponse::from_der(&bytes[..]) {
            assert_eq!(
                response.to_der().unwrap(),
                bytes,
                "{name} does not re-encode to itself"
            );
            responses += 1;
            continue;
        }
        let parsed: Result<OcspRequest, _> = OcspRequest::from_der(&bytes[..]);
        if let Ok(request) = parsed {
            assert_eq!(
                request.to_der().unwrap(),
                bytes,
                "{name} does not re-encode to itself"
            );
            requests += 1;
            continue;
        }
        skipped += 1;
    }

    println!("{requests} requests, {responses} responses, {skipped} not messages");

    // A sweep that decoded nothing would satisfy every assertion above this one.
    assert_eq!(
        (requests, responses),
        (REQUESTS, RESPONSES),
        "expected {REQUESTS} requests and {RESPONSES} responses, got {requests} and {responses} \
         ({skipped} files decoded as neither). A message that stops decoding is skipped rather \
         than failed, so a shortfall here is the symptom worth chasing."
    );
}
