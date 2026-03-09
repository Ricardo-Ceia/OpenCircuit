use std::process::Command;

#[test]
fn normalize_command_outputs_network_cidr() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["normalize", "192.168.1.42/24"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "192.168.1.0/24\n");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

#[test]
fn normalize_command_fails_for_invalid_cidr() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["normalize", "not-an-ip/24"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Invalid CIDR"));
}

#[test]
fn normalize_command_fails_with_missing_argument() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .arg("normalize")
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("Usage: opencircuit normalize <ipv4-cidr>"));
}
