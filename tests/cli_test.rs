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
        .contains("Usage:\n  opencircuit normalize <ipv4-cidr>\n  opencircuit info <ipv4-cidr>\n  opencircuit contains <ipv4-cidr> <ipv4-address>\n  opencircuit classify <ipv4-address>\n  opencircuit summary <ipv4-cidr>"));
}

#[test]
fn info_command_outputs_cidr_details() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["info", "192.168.1.42/24"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "cidr=192.168.1.0/24\nnetwork=192.168.1.0\nbroadcast=192.168.1.255\nfirst_usable=192.168.1.1\nlast_usable=192.168.1.254\n"
    );
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

#[test]
fn info_command_fails_for_invalid_cidr() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["info", "bad/24"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Invalid CIDR"));
}

#[test]
fn contains_command_outputs_true_when_ip_is_in_cidr() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["contains", "192.168.1.0/24", "192.168.1.42"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "true\n");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

#[test]
fn contains_command_outputs_false_when_ip_is_outside_cidr() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["contains", "192.168.1.0/24", "192.168.2.10"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "false\n");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

#[test]
fn contains_command_fails_for_invalid_ip_argument() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["contains", "192.168.1.0/24", "nope"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Invalid IPv4 address"));
}

#[test]
fn classify_command_outputs_expected_flags() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["classify", "192.168.1.10"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "ip=192.168.1.10\nprivate=true\nlink_local=false\nloopback=false\nmulticast=false\n"
    );
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

#[test]
fn classify_command_detects_link_local_and_loopback_separately() {
    let link_local = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["classify", "169.254.1.20"])
        .output()
        .expect("failed to run opencircuit binary");
    let loopback = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["classify", "127.0.0.1"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(link_local.status.success());
    assert!(String::from_utf8_lossy(&link_local.stdout).contains("link_local=true"));
    assert!(loopback.status.success());
    assert!(String::from_utf8_lossy(&loopback.stdout).contains("loopback=true"));
}

#[test]
fn classify_command_fails_for_invalid_ip() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["classify", "nope"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Invalid IPv4 address"));
}

#[test]
fn summary_command_outputs_compact_network_metrics() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["summary", "192.168.1.42/24"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "cidr=192.168.1.0/24 total=256 usable=254\n"
    );
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

#[test]
fn summary_command_fails_for_invalid_cidr() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["summary", "nope/24"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Invalid CIDR"));
}
