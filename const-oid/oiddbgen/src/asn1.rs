use std::collections::{BTreeMap, HashSet};

use regex::Regex;

#[derive(Clone, Debug)]
pub struct Asn1Parser {
    spec: String,
    tree: BTreeMap<String, (Option<String>, Option<String>)>,
}

impl Asn1Parser {
    const DEF: &'static str = r"(?mx)
        (?P<name>[a-z][a-zA-Z0-9-]*)                # name
        \s+
        OBJECT
        \s+
        IDENTIFIER
        \s*
        ::=
        \s*
        \{
            \s*
            (?:(?P<base>[a-z][a-zA-Z0-9-]*)\s+)?    # base
            (?P<tail>                               # tail
                (?:
                    (?:
                        [a-z][a-zA-Z0-9-]*\([0-9]+\)\s+
                    )
                    |
                    (?:
                        [0-9]+\s+
                    )
                )*
            )
        \}
    ";

    const ARC: &'static str = r"(?mx)
        (?:
            [a-z][a-zA-Z0-9-]*\(([0-9]+)\)
        )
        |
        (?:
            ([0-9]+)
        )
    ";

    pub fn new(spec: String, asn1: &str) -> Self {
        let def = Regex::new(Self::DEF).unwrap();
        let arc = Regex::new(Self::ARC).unwrap();

        let mut tree = BTreeMap::default();
        for mat in def.find_iter(asn1) {
            let caps = def.captures(mat.as_str()).unwrap();
            let name = caps.name("name").unwrap().as_str().to_owned();
            let base = caps.name("base").map(|m| m.as_str().to_string());
            let tail = caps.name("tail").map(|m| {
                arc.find_iter(m.as_str())
                    .map(|m| {
                        let c = arc.captures(m.as_str()).unwrap();
                        c.get(1).unwrap_or_else(|| c.get(2).unwrap()).as_str()
                    })
                    .collect::<Vec<_>>()
                    .join(".")
            });

            tree.insert(name, (base, tail));
        }

        Self { spec, tree }
    }

    pub fn resolve(&self, name: &str) -> Option<String> {
        let (base, arcs) = self.tree.get(name)?;
        if let Some(base) = base {
            let base = self.resolve(base)?;
            if let Some(arcs) = arcs {
                Some(format!("{}.{}", base, arcs))
            } else {
                Some(base)
            }
        } else {
            arcs.clone()
        }
    }

    pub fn iter(&self) -> impl '_ + Iterator<Item = (String, String, String)> {
        let bases: HashSet<&String> = self
            .tree
            .values()
            .filter_map(|(base, ..)| base.as_ref())
            .collect();

        self.tree
            .keys()
            .filter(move |n| !bases.contains(n))
            .filter_map(|n| self.resolve(n).map(|p| (self.spec.clone(), n.clone(), p)))
    }
}

#[test]
fn test() {
    let asn1 = super::Asn1Parser::new(
        "none".into(),
        r"
            foo OBJECT IDENTIFIER ::= { bar(1) baz(2) 3 }
            bat OBJECT IDENTIFIER ::= { foo qux(4) 5 }
            quz OBJECT IDENTIFIER ::= { bat 6 }
        ",
    );

    let answer = (
        "none".to_string(),
        "quz".to_string(),
        "1.2.3.4.5.6".to_string(),
    );

    let mut iter = asn1.iter();
    assert_eq!(Some(answer), iter.next());
    assert_eq!(None, iter.next());
}
