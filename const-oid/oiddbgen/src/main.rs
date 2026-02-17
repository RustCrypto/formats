use oiddbgen::{Asn1Parser, LdapParser, Root};

// Update this database by downloading the CSV file here:
// https://www.iana.org/assignments/ldap-parameters/ldap-parameters.xhtml#ldap-parameters-3
const LDAP: &str = include_str!("../ldap-parameters-3.csv");

// All RFCs downloaded from:
// https://www.rfc-editor.org/rfc/rfcNNNN.txt
const RFCS: &[(&str, &str)] = &[
    ("rfc2985", include_str!("../rfc2985.txt")),
    ("rfc3161", include_str!("../rfc3161.txt")),
    ("rfc5280", include_str!("../rfc5280.txt")),
    ("rfc5753", include_str!("../rfc5753.txt")),
    ("rfc5911", include_str!("../rfc5911.txt")),
    ("rfc5912", include_str!("../rfc5912.txt")),
    ("rfc6268", include_str!("../rfc6268.txt")),
    ("rfc6960", include_str!("../rfc6960.txt")),
    ("rfc6962", include_str!("../rfc6962.txt")),
    ("rfc7107", include_str!("../rfc7107.txt")),
    ("rfc7292", include_str!("../rfc7292.txt")),
    ("rfc7299", include_str!("../rfc7299.txt")),
    ("rfc7693", include_str!("../rfc7693.txt")),
    ("rfc8410", include_str!("../rfc8410.txt")),
    ("rfc5639", include_str!("../rfc5639.txt")),
    ("rfc9688", include_str!("../rfc9688.txt")),
];

const MDS: &[(&str, &str)] = &[
    // Created from:
    // https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
    ("fips202", include_str!("../fips202.md")),
    ("fips203", include_str!("../fips203.md")),
    ("fips204", include_str!("../fips204.md")),
    ("fips205", include_str!("../fips205.md")),
    ("rfc8894", include_str!("../rfc8894.md")),
    // Created from: https://trustedcomputinggroup.org
    ("tcgtpm", include_str!("../tcg-tpm.md")),
    // Created from:  https://github.com/bcrypto
    ("belt", include_str!("../stb/belt.asn")),
    ("bign", include_str!("../stb/bign.asn")),
    ("bpki", include_str!("../stb/bpki.asn")),
    ("btok", include_str!("../stb/btok.asn")),
    ("brng", include_str!("../stb/brng.asn")),
    ("bash", include_str!("../stb/bash.asn")),
    ("bake", include_str!("../stb/bake.asn")),
    // created from: https://oidref.com/1.3.6.1.4.1.311
    ("microsoft", include_str!("../microsoft.asn")),

    // loaded from https://web.mit.edu/kerberos/krb5-oids/krb5-oids.asn
    ("kerberosv5", include_str!("../krb5-oids.asn")),
];

// Bases defined in other places.
const BASES: &[(&str, &str)] = &[
    ("id-ad-ocsp", "1.3.6.1.5.5.7.48.1"),
    ("ecStdCurvesAndGeneration", "1.3.36.3.3.2.8"),
];
const NO_BASES: &[(&str, &str)] = &[("", "")];

fn main() {
    let mut root = Root::default();

    for (spec, name, obid) in LdapParser::new(LDAP).iter() {
        root.add(&spec, &name, &obid);
    }

    for (spec, body) in RFCS {
        for (name, obid) in Asn1Parser::new(body, BASES).iter() {
            root.add(spec, &name, &obid);
        }
    }

    for (spec, body) in MDS {
        for (name, obid) in Asn1Parser::new(body, NO_BASES).iter() {
            root.add(spec, &name, &obid);
        }
    }

    println!("{}", root.module());
}
