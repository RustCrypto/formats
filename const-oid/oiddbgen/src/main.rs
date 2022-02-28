use oiddbgen::{Asn1Parser, LdapParser, Root};

// Update this database by downloading the CSV file here:
// https://www.iana.org/assignments/ldap-parameters/ldap-parameters.xhtml#ldap-parameters-3
const LDAP: &str = include_str!("../ldap-parameters-3.csv");

// Downloaded from:
// https://www.rfc-editor.org/rfc/rfc5280.txt
const RFC5280: &str = include_str!("../rfc5280.txt");

fn main() {
    let mut root = Root::default();

    for (spec, name, obid) in LdapParser::new(LDAP).iter() {
        root.add(&spec, &name, &obid)
    }

    for (spec, name, obid) in Asn1Parser::new("rfc5280".into(), RFC5280).iter() {
        root.add(&spec, &name, &obid)
    }

    println!("{}", root.module());
}
