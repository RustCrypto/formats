use std::{
    fs::{self, File},
    io::{Read, Write},
    process::{Command, ExitStatus, Stdio},
};
use tempfile::tempdir;

fn check_openssl_output(command_and_args: &[&str], pem: &[u8]) -> String {
    let tmp_dir = tempdir().expect("create tempdir");
    let cert_path = tmp_dir.path().join("cert.pem");

    let mut cert_file = File::create(&cert_path).expect("create pem file");
    cert_file.write_all(pem).expect("Create pem file");

    let mut child = Command::new("openssl")
        .args(command_and_args)
        .arg("-in")
        .arg(&cert_path)
        .arg("-noout")
        .arg("-text")
        .stderr(Stdio::inherit())
        .stdout(Stdio::piped())
        .spawn()
        .expect("openssl failed");
    let mut stdout = child.stdout.take().unwrap();
    let exit_status = child.wait().expect("get openssl x509 status");

    assert!(exit_status.success(), "openssl failed");
    let mut output_buf = Vec::new();
    stdout
        .read_to_end(&mut output_buf)
        .expect("read openssl output");

    String::from_utf8(output_buf.clone()).unwrap()
}

pub fn check_certificate(pem: &[u8]) -> String {
    check_openssl_output(&["x509"], pem)
}

pub fn check_crl(pem: &[u8]) -> String {
    check_openssl_output(&["crl"], pem)
}

pub fn check_request(pem: &[u8]) -> String {
    check_openssl_output(&["req", "-verify"], pem)
}

pub fn verify(trust_anchor: &[u8], leaf: &[u8], crl: &[u8]) -> (ExitStatus, String, String) {
    let tmp_dir = tempdir().expect("create tempdir");
    let trust_anchor_path = tmp_dir.path().join("trust_anchor.pem");
    let leaf_path = tmp_dir.path().join("leaf.pem");
    let crl_path = tmp_dir.path().join("crl.pem");

    fs::write(&trust_anchor_path, trust_anchor).expect("Write trust anchor");
    fs::write(&leaf_path, leaf).expect("Write leaf");
    fs::write(&crl_path, crl).expect("Write crl");

    let mut child = Command::new("openssl")
        .arg("verify")
        .arg("-crl_check")
        .arg("-CRLfile")
        .arg(&crl_path)
        .arg("-trusted")
        .arg(&trust_anchor_path)
        .arg("--")
        .arg(&leaf_path)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("openssl failed");
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();

    let mut output_buf = Vec::new();
    stdout
        .read_to_end(&mut output_buf)
        .expect("read openssl output");
    let mut stderr_buf = Vec::new();
    stderr
        .read_to_end(&mut stderr_buf)
        .expect("read openssl output");
    let exit_status = child.wait().expect("get openssl verify status");

    (
        exit_status,
        String::from_utf8(output_buf.clone()).unwrap(),
        String::from_utf8(stderr_buf.clone()).unwrap(),
    )
}
