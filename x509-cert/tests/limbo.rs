//! C2SP x509-limbo certificate decoding tests.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use serde_json::Value;
use x509_cert::{
    Certificate,
    der::{Decode, Document, Encode},
    ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, NameConstraints, SubjectAltName},
};

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum LimboFixture {
    Cases(Vec<Value>),
    Suite {
        #[serde(default, alias = "testCases", alias = "tests")]
        testcases: Vec<Value>,
    },
}

impl LimboFixture {
    fn testcases(&self) -> &[Value] {
        match self {
            Self::Cases(testcases) | Self::Suite { testcases } => testcases,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ExpectedResult {
    Success,
    Failure,
    Unknown,
}

#[derive(Debug)]
struct CertInput {
    role: String,
    pem: String,
}

#[derive(Debug, Default)]
struct LimboReport {
    total: usize,
    expected_success: usize,
    expected_success_decoded: usize,
    expected_failure: usize,
    expected_failure_rejected: usize,
    expected_failure_decoded: usize,
    unknown_expected_result: usize,
    certificates_checked: usize,
    field_check_failures: Vec<String>,
    expected_success_decode_failures: Vec<String>,
    expected_failure_decoded_without_error: Vec<String>,
    malformed_failures_decoded_without_error: Vec<String>,
    features: BTreeMap<String, usize>,
}

impl LimboReport {
    fn record_features(&mut self, features: &BTreeSet<String>) {
        for feature in features {
            *self.features.entry(feature.clone()).or_default() += 1;
        }
    }

    fn summary(&self) -> String {
        let mut summary = String::new();

        let _ = writeln!(summary, "x509-limbo decode report");
        let _ = writeln!(summary, "  total testcases: {}", self.total);
        let _ = writeln!(
            summary,
            "  certificates checked: {}",
            self.certificates_checked
        );
        let _ = writeln!(
            summary,
            "  expected-pass decoded: {}/{}",
            self.expected_success_decoded, self.expected_success
        );
        let _ = writeln!(
            summary,
            "  expected-fail rejected by Certificate::from_der: {}/{}",
            self.expected_failure_rejected, self.expected_failure
        );
        let _ = writeln!(
            summary,
            "  expected-fail decoded without Certificate::from_der error: {}",
            self.expected_failure_decoded
        );
        let _ = writeln!(
            summary,
            "  unknown expected_result testcases: {}",
            self.unknown_expected_result
        );

        append_list(
            &mut summary,
            "first expected-pass decode failures",
            &self.expected_success_decode_failures,
        );
        append_list(
            &mut summary,
            "first expected-fail cases decoded without error",
            &self.expected_failure_decoded_without_error,
        );
        append_list(
            &mut summary,
            "first malformed-cert failures decoded without error",
            &self.malformed_failures_decoded_without_error,
        );
        append_list(
            &mut summary,
            "first field-level invariant failures",
            &self.field_check_failures,
        );

        if !self.features.is_empty() {
            let _ = writeln!(summary, "  feature inventory:");
            for (feature, count) in &self.features {
                let _ = writeln!(summary, "    {feature}: {count}");
            }
        }

        summary
    }
}

#[test]
fn limbo_decode_round_trips() {
    let Some(fixture) = load_limbo_fixture() else {
        return;
    };

    let mut report = LimboReport::default();

    for (index, testcase) in fixture.testcases().iter().enumerate() {
        report.total += 1;

        let id = testcase_id(testcase, index);
        let expected = expected_result(testcase);
        let features = feature_names(testcase);
        let certs = certificate_inputs(testcase);
        report.record_features(&features);
        report.certificates_checked += certs.len();

        let mut all_decoded = !certs.is_empty();
        let mut decode_errors = Vec::new();

        if certs.is_empty() {
            all_decoded = false;
            decode_errors.push("no PEM certificates found in testcase".to_owned());
        }

        for cert in &certs {
            match decode_round_trip(&cert.pem) {
                Ok(certificate) => {
                    if let Err(err) = exercise_field_decoders(&certificate) {
                        push_first_ten(
                            &mut report.field_check_failures,
                            format!("{id} {}: {err}", cert.role),
                        );
                    }
                }
                Err(err) => {
                    all_decoded = false;
                    decode_errors.push(format!("{}: {err}", cert.role));
                }
            }
        }

        match expected {
            ExpectedResult::Success => {
                report.expected_success += 1;
                if all_decoded {
                    report.expected_success_decoded += 1;
                } else {
                    push_first_ten(
                        &mut report.expected_success_decode_failures,
                        format!("{id}: {}", decode_errors.join("; ")),
                    );
                }
            }
            ExpectedResult::Failure => {
                report.expected_failure += 1;
                if all_decoded {
                    report.expected_failure_decoded += 1;
                    push_first_ten(
                        &mut report.expected_failure_decoded_without_error,
                        id.clone(),
                    );

                    if is_malformed_cert_failure(testcase, &features) {
                        push_first_ten(&mut report.malformed_failures_decoded_without_error, id);
                    }
                } else {
                    report.expected_failure_rejected += 1;
                }
            }
            ExpectedResult::Unknown => {
                report.unknown_expected_result += 1;
            }
        }
    }

    println!("{}", report.summary());

    assert!(
        report.expected_success_decode_failures.is_empty(),
        "{}",
        report.summary()
    );

    assert!(
        report.malformed_failures_decoded_without_error.is_empty(),
        "{}",
        report.summary()
    );
}

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/limbo/limbo.json")
}

fn load_limbo_fixture() -> Option<LimboFixture> {
    let path = fixture_path();
    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "skipping x509-limbo tests: fixture not found at {}",
                path.display()
            );
            return None;
        }
        Err(err) => panic!("failed to read {}: {err}", path.display()),
    };

    Some(
        serde_json::from_str(&contents)
            .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display())),
    )
}

fn decode_round_trip(pem: &str) -> Result<Certificate, String> {
    let (label, document) = Document::from_pem(pem.trim())
        .map_err(|err| format!("PEM/DER document decode failed: {err}"))?;

    if label != "CERTIFICATE" {
        return Err(format!("unexpected PEM label {label:?}"));
    }

    let certificate = Certificate::from_der(document.as_bytes())
        .map_err(|err| format!("Certificate::from_der failed: {err}"))?;
    let encoded = certificate
        .to_der()
        .map_err(|err| format!("Certificate::to_der failed: {err}"))?;

    if encoded != document.as_bytes() {
        return Err(format!(
            "DER round-trip changed encoding length from {} to {} bytes",
            document.as_bytes().len(),
            encoded.len()
        ));
    }

    let reparsed = Certificate::from_der(&encoded)
        .map_err(|err| format!("reparse of round-tripped DER failed: {err}"))?;
    let reencoded = reparsed
        .to_der()
        .map_err(|err| format!("re-encode of reparsed DER failed: {err}"))?;

    if reencoded != encoded {
        return Err("second DER round-trip changed encoding".to_owned());
    }

    Ok(certificate)
}

fn exercise_field_decoders(certificate: &Certificate) -> Result<(), String> {
    let tbs = certificate.tbs_certificate();
    let validity = tbs.validity();

    if validity.not_before.to_unix_duration() > validity.not_after.to_unix_duration() {
        return Err(format!(
            "validity not_before {} is after not_after {}",
            validity.not_before, validity.not_after
        ));
    }

    if let Some((_critical, basic_constraints)) = tbs
        .get_extension::<BasicConstraints>()
        .map_err(|err| format!("basicConstraints extension decode failed: {err}"))?
    {
        let _ca_flag = basic_constraints.ca;
    }

    if let Some((critical, _key_usage)) = tbs
        .get_extension::<KeyUsage>()
        .map_err(|err| format!("keyUsage extension decode failed: {err}"))?
    {
        let _key_usage_criticality = critical;
    }

    if let Some((_critical, extended_key_usage)) = tbs
        .get_extension::<ExtendedKeyUsage>()
        .map_err(|err| format!("extendedKeyUsage extension decode failed: {err}"))?
    {
        let _eku_present = !extended_key_usage.0.is_empty();
    }

    if let Some((_critical, subject_alt_name)) = tbs
        .get_extension::<SubjectAltName>()
        .map_err(|err| format!("subjectAltName extension decode failed: {err}"))?
    {
        let _san_present = !subject_alt_name.0.is_empty();
    }

    let _name_constraints = tbs
        .get_extension::<NameConstraints>()
        .map_err(|err| format!("nameConstraints extension decode failed: {err}"))?;

    Ok(())
}

fn append_list(summary: &mut String, title: &str, items: &[String]) {
    if items.is_empty() {
        return;
    }

    let _ = writeln!(summary, "  {title}:");
    for item in items {
        let _ = writeln!(summary, "    - {item}");
    }
}

fn push_first_ten(items: &mut Vec<String>, item: String) {
    if items.len() < 10 {
        items.push(item);
    }
}

fn testcase_id(testcase: &Value, index: usize) -> String {
    field_string(
        testcase,
        &[
            "id",
            "testcase",
            "testcase_id",
            "testcaseId",
            "name",
            "description",
        ],
    )
    .unwrap_or_else(|| format!("case-{index}"))
}

fn expected_result(testcase: &Value) -> ExpectedResult {
    let Some(value) = field_string(
        testcase,
        &[
            "expected_result",
            "expectedResult",
            "expected",
            "result",
            "outcome",
        ],
    ) else {
        return ExpectedResult::Unknown;
    };

    let uppercase = value.to_ascii_uppercase();
    if uppercase.contains("SUCCESS") || uppercase == "PASS" || uppercase == "VALID" {
        ExpectedResult::Success
    } else if uppercase.contains("FAIL") || uppercase.contains("ERROR") || uppercase == "INVALID" {
        ExpectedResult::Failure
    } else {
        ExpectedResult::Unknown
    }
}

fn certificate_inputs(testcase: &Value) -> Vec<CertInput> {
    let mut certificates = Vec::new();

    append_certificates(
        testcase,
        &[
            "peer_certificate",
            "peerCertificate",
            "leaf_certificate",
            "leafCertificate",
            "leaf_cert",
            "leafCert",
            "leaf",
            "cert",
            "certificate",
        ],
        "leaf",
        &mut certificates,
    );
    append_certificates(
        testcase,
        &[
            "untrusted_intermediates",
            "untrustedIntermediates",
            "intermediates",
            "intermediate_certs",
            "intermediateCerts",
            "intermediate_certificates",
            "intermediateCertificates",
        ],
        "intermediate",
        &mut certificates,
    );
    append_certificates(
        testcase,
        &[
            "trusted_certs",
            "trustedCerts",
            "trusted_roots",
            "trustedRoots",
            "roots",
            "trust_anchors",
            "trustAnchors",
        ],
        "root",
        &mut certificates,
    );

    if certificates.is_empty() {
        let mut pems = Vec::new();
        collect_pem_strings(testcase, &mut pems);
        for (index, pem) in pems.into_iter().enumerate() {
            certificates.push(CertInput {
                role: format!("certificate[{index}]"),
                pem,
            });
        }
    }

    certificates
}

fn append_certificates(
    testcase: &Value,
    keys: &[&str],
    role: &str,
    certificates: &mut Vec<CertInput>,
) {
    let Some(value) = find_field(testcase, keys) else {
        return;
    };

    let mut pems = Vec::new();
    collect_pem_strings(value, &mut pems);

    for (index, pem) in pems.into_iter().enumerate() {
        certificates.push(CertInput {
            role: format!("{role}[{index}]"),
            pem,
        });
    }
}

fn collect_pem_strings(value: &Value, output: &mut Vec<String>) {
    match value {
        Value::String(value) if value.contains("BEGIN CERTIFICATE") => {
            output.push(value.clone());
        }
        Value::Array(values) => {
            for value in values {
                collect_pem_strings(value, output);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_pem_strings(value, output);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn feature_names(testcase: &Value) -> BTreeSet<String> {
    let mut features = BTreeSet::new();

    if let Some(value) = find_field(testcase, &["features", "feature", "feature_tags"]) {
        collect_feature_names(value, &mut features);
    }

    features
}

fn collect_feature_names(value: &Value, features: &mut BTreeSet<String>) {
    match value {
        Value::String(value) => {
            features.insert(normalize_feature(value));
        }
        Value::Array(values) => {
            for value in values {
                collect_feature_names(value, features);
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                features.insert(normalize_feature(key));
                collect_feature_names(value, features);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn is_malformed_cert_failure(testcase: &Value, features: &BTreeSet<String>) -> bool {
    if features.iter().any(|feature| {
        feature == "malformed-cert" || feature.contains("malformed") || feature.contains("asn1")
    }) {
        return true;
    }

    [
        "failure_kind",
        "failureKind",
        "failure_reason",
        "failureReason",
        "expected_error",
        "expectedError",
        "reason",
    ]
    .iter()
    .filter_map(|key| field_string(testcase, &[*key]))
    .any(|reason| {
        let reason = normalize_feature(&reason);
        reason == "malformed-cert" || reason.contains("malformed") || reason.contains("asn1")
    })
}

fn field_string(value: &Value, keys: &[&str]) -> Option<String> {
    find_field(value, keys).and_then(value_to_string)
}

fn find_field<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    let Value::Object(values) = value else {
        return None;
    };

    for key in keys {
        if let Some(value) = values.get(*key) {
            return Some(value);
        }
    }

    values.iter().find_map(|(candidate, value)| {
        keys.iter()
            .any(|key| normalize_key(candidate) == normalize_key(key))
            .then_some(value)
    })
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::Object(values) => ["kind", "type", "value", "result", "expected"]
            .iter()
            .filter_map(|key| values.get(*key))
            .find_map(value_to_string),
        Value::Array(values) => values.first().and_then(value_to_string),
        Value::Null => None,
    }
}

fn normalize_key(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn normalize_feature(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace(['_', ' '], "-")
}
