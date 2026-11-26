//! PEM decoding tests

#[test]
fn pkcs1_example() {
    let pem = include_bytes!("examples/pkcs1.pem");
    let mut buf = [0u8; 2048];
    let (label, decoded) = pem_rfc7468::decode(pem, &mut buf).unwrap();
    assert_eq!(label, "RSA PRIVATE KEY");
    assert_eq!(decoded, include_bytes!("examples/pkcs1.der"));
}

#[test]
fn binary_example() {
    let der = include_bytes!("examples/pkcs1.der");
    let mut buf = [0u8; 2048];
    match pem_rfc7468::decode(der, &mut buf) {
        Err(pem_rfc7468::Error::Preamble) => (),
        _ => panic!("Expected Preamble error"),
    }
}

#[test]
fn pkcs1_example_with_preceding_junk() {
    let pem = include_bytes!("examples/pkcs1_with_preceding_junk.pem");
    let mut buf = [0u8; 2048];
    let (label, decoded) = pem_rfc7468::decode(pem, &mut buf).unwrap();
    assert_eq!(label, "RSA PRIVATE KEY");
    assert_eq!(decoded, include_bytes!("examples/pkcs1.der"));
}

#[test]
fn pkcs1_enc_example() {
    let pem = include_bytes!("examples/ssh_rsa_pem_password.pem");
    let mut buf = [0u8; 2048];
    let result = pem_rfc7468::decode(pem, &mut buf);
    assert_eq!(result, Err(pem_rfc7468::Error::HeaderDisallowed));

    let label = pem_rfc7468::decode_label(pem).unwrap();
    assert_eq!(label, "RSA PRIVATE KEY");
}

#[test]
#[cfg(feature = "alloc")]
fn pkcs1_enc_example_with_vec() {
    let pem = include_bytes!("examples/ssh_rsa_pem_password.pem");
    let result = pem_rfc7468::decode_vec(pem);
    assert_eq!(result, Err(pem_rfc7468::Error::HeaderDisallowed));
}

#[test]
fn header_of_length_64() {
    let pem = include_bytes!("examples/chosen_header.pem");
    let mut buf = [0u8; 2048];
    let result = pem_rfc7468::decode(pem, &mut buf);
    assert_eq!(result, Err(pem_rfc7468::Error::HeaderDisallowed));

    let label = pem_rfc7468::decode_label(pem).unwrap();
    assert_eq!(label, "RSA PRIVATE KEY");
}

#[test]
#[cfg(feature = "alloc")]
fn header_of_length_64_with_vec() {
    let pem = include_bytes!("examples/chosen_header.pem");
    match pem_rfc7468::decode_vec(pem) {
        Err(pem_rfc7468::Error::HeaderDisallowed) => (),
        res => panic!("Expected HeaderDisallowed error; Found {res:?}"),
    }
}

#[test]
fn pkcs8_example() {
    let pem = include_bytes!("examples/pkcs8.pem");
    let mut buf = [0u8; 2048];
    let (label, decoded) = pem_rfc7468::decode(pem, &mut buf).unwrap();
    assert_eq!(label, "PRIVATE KEY");
    assert_eq!(decoded, include_bytes!("examples/pkcs8.der"));
}

#[test]
fn pkcs8_enc_example() {
    let pem = include_bytes!("examples/pkcs8-enc.pem");
    let mut buf = [0u8; 2048];
    let (label, decoded) = pem_rfc7468::decode(pem, &mut buf).unwrap();
    assert_eq!(label, "ENCRYPTED PRIVATE KEY");
    assert_eq!(decoded, include_bytes!("examples/pkcs8-enc.der"));
}

#[test]
#[cfg(feature = "alloc")]
fn pkcs1_example_with_vec() {
    let pem = include_bytes!("examples/pkcs1.pem");
    let (label, decoded) = pem_rfc7468::decode_vec(pem).unwrap();
    assert_eq!(label, "RSA PRIVATE KEY");
    assert_eq!(decoded, include_bytes!("examples/pkcs1.der"));
}

#[test]
#[cfg(feature = "alloc")]
fn pkcs8_enc_example_with_vec() {
    let pem = include_bytes!("examples/pkcs8-enc.pem");
    let (label, decoded) = pem_rfc7468::decode_vec(pem).unwrap();
    assert_eq!(label, "ENCRYPTED PRIVATE KEY");
    assert_eq!(decoded, include_bytes!("examples/pkcs8-enc.der"));
}

#[test]
fn ed25519_example() {
    let pem = include_bytes!("examples/ed25519_id.pem");
    let label = pem_rfc7468::decode_label(pem).unwrap();
    assert_eq!(label, "ED25519 CERT");
}

#[test]
fn line_width_detection() {
    let pem_64cols = include_bytes!("examples/pkcs1.pem");
    assert_eq!(
        pem_rfc7468::detect_base64_line_width(pem_64cols).unwrap(),
        64
    );

    let pem_70cols = include_bytes!("examples/ssh-id_ed25519.pem");
    assert_eq!(
        pem_rfc7468::detect_base64_line_width(pem_70cols).unwrap(),
        70
    );
}

/// RFC 7468 Section 3: `eol = CRLF / CR / LF`. A preamble line ended by a
/// lone CR must still find the pre-encapsulation boundary after it.
#[test]
fn preamble_ended_by_lone_cr() {
    const PEM: &[u8] = include_bytes!("examples/pkcs1.pem");
    const DER: &[u8] = include_bytes!("examples/pkcs1.der");
    let mut input = [0u8; PEM.len() + 6];
    input[..5].copy_from_slice(b"chain");
    input[5] = 0x0D;
    input[6..].copy_from_slice(PEM);
    let mut buf = [0u8; 2048];
    let (label, decoded) = pem_rfc7468::decode(&input, &mut buf).unwrap();
    assert_eq!(label, "RSA PRIVATE KEY");
    assert_eq!(decoded, DER);
}

/// The second message of a chain, as callers that split on the
/// post-encapsulation boundary hand it over: the previous message's trailing
/// lone CR in front, and every line end of the message itself a lone CR.
#[test]
fn lone_cr_line_endings_after_preceding_text() {
    const PEM: &[u8] = include_bytes!("examples/pkcs1.pem");
    const DER: &[u8] = include_bytes!("examples/pkcs1.der");
    let mut input = [0u8; PEM.len() + 6];
    input[..5].copy_from_slice(b"chain");
    input[5] = 0x0D;
    for (i, &byte) in PEM.iter().enumerate() {
        input[6 + i] = if byte == 0x0A { 0x0D } else { byte };
    }
    let mut buf = [0u8; 2048];
    let (label, decoded) = pem_rfc7468::decode(&input, &mut buf).unwrap();
    assert_eq!(label, "RSA PRIVATE KEY");
    assert_eq!(decoded, DER);
}

/// A bare eol in front of the boundary, with no preamble text at all.
#[test]
fn boundary_after_lone_cr() {
    const PEM: &[u8] = include_bytes!("examples/pkcs1.pem");
    let mut input = [0u8; PEM.len() + 1];
    input[0] = 0x0D;
    input[1..].copy_from_slice(PEM);
    assert_eq!(
        pem_rfc7468::decode_label(&input).unwrap(),
        "RSA PRIVATE KEY"
    );
}

/// The CRLF path is unchanged: the CR arm must not consume a CR that an LF
/// follows, and the boundary after the LF is still found.
#[test]
fn preamble_ended_by_crlf() {
    const PEM: &[u8] = include_bytes!("examples/pkcs1.pem");
    const DER: &[u8] = include_bytes!("examples/pkcs1.der");
    let mut input = [0u8; PEM.len() + 7];
    input[..5].copy_from_slice(b"chain");
    input[5] = 0x0D;
    input[6] = 0x0A;
    input[7..].copy_from_slice(PEM);
    let mut buf = [0u8; 2048];
    let (label, decoded) = pem_rfc7468::decode(&input, &mut buf).unwrap();
    assert_eq!(label, "RSA PRIVATE KEY");
    assert_eq!(decoded, DER);
}

/// The OpenSSL-inspired NUL refusal still applies to a preamble that never
/// reaches the boundary.
#[test]
fn preamble_with_nul_byte_is_still_refused() {
    const PEM: &[u8] = include_bytes!("examples/pkcs1.pem");
    let mut input = [0u8; PEM.len() + 6];
    input[..3].copy_from_slice(b"cha");
    input[3] = 0x00;
    input[4] = b'n';
    input[5] = 0x0D;
    input[6..].copy_from_slice(PEM);
    let mut buf = [0u8; 2048];
    let result = pem_rfc7468::decode(&input, &mut buf);
    assert_eq!(result, Err(pem_rfc7468::Error::Preamble));
}

#[test]
#[cfg(feature = "alloc")]
fn lone_cr_chain_with_vec() {
    const PEM: &[u8] = include_bytes!("examples/pkcs1.pem");
    const DER: &[u8] = include_bytes!("examples/pkcs1.der");
    let mut input = [0u8; PEM.len() + 6];
    input[..5].copy_from_slice(b"chain");
    input[5] = 0x0D;
    for (i, &byte) in PEM.iter().enumerate() {
        input[6 + i] = if byte == 0x0A { 0x0D } else { byte };
    }
    let (label, decoded) = pem_rfc7468::decode_vec(&input).unwrap();
    assert_eq!(label, "RSA PRIVATE KEY");
    assert_eq!(decoded, DER);
}
