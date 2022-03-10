use oiddbgen::{Asn1Parser, LdapParser, Root};

// Update this database by downloading the CSV file here:
// https://www.iana.org/assignments/ldap-parameters/ldap-parameters.xhtml#ldap-parameters-3
const LDAP: &str = include_str!("../ldap-parameters-3.csv");

// All RFCs downloaded from:
// https://www.rfc-editor.org/rfc/rfcNNNN.txt
const RFCS: &[(&str, &str)] = &[
    ("rfc5280", include_str!("../rfc5280.txt")),
    ("rfc5911", include_str!("../rfc5911.txt")),
    ("rfc5912", include_str!("../rfc5912.txt")),
    ("rfc6268", include_str!("../rfc6268.txt")),
    ("rfc6960", include_str!("../rfc6960.txt")),
    ("rfc7107", include_str!("../rfc7107.txt")),
    ("rfc7299", include_str!("../rfc7299.txt")),
];

// Bases defined in other places.
const BASES: &[(&str, &str)] = &[("id-ad-ocsp", "1.3.6.1.5.5.7.48.1")];

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

    println!("{}", root.module());
}
