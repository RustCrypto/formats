use oiddbgen::Root;

// Update this database by downloading the CSV file here:
// https://www.iana.org/assignments/ldap-parameters/ldap-parameters.xhtml#ldap-parameters-3
const LDAP: &str = include_str!("../ldap-parameters-3.csv");

// Downloaded from:
// https://www.rfc-editor.org/rfc/rfc5280.txt
const RFC5280: &str = include_str!("../rfc5280.txt");

fn rfc5280() -> impl Iterator<Item = String> {
    const RE: &str = "^(id-ce-[a-zA-Z0-9-]+) +OBJECT +IDENTIFIER *::= *\\{ *id-ce +(\\d+) *\\}";

    let re = regex::Regex::new(RE).unwrap();
    RFC5280
        .lines()
        .filter_map(move |line| re.captures(line))
        .map(|cap| {
            let obji = format!("2.5.29.{}", cap.get(2).unwrap().as_str());
            let name = cap.get(1).unwrap().as_str();
            format!("{},X,{},[RFC5280]", name, obji)
        })
}

fn main() {
    let mut root = Root::default();

    for line in LDAP.lines().skip(1) {
        root.parse_line(line);
    }

    for line in rfc5280() {
        root.parse_line(&line);
    }

    println!("{}", root.module());
}
