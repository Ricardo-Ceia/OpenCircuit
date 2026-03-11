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
        .contains("Usage:\n  opencircuit normalize <ipv4-cidr>\n  opencircuit info <ipv4-cidr>\n  opencircuit contains <ipv4-cidr> <ipv4-address>\n  opencircuit usable <ipv4-cidr> <ipv4-address>\n  opencircuit next <ipv4-address>\n  opencircuit prev <ipv4-address>\n  opencircuit classify <ipv4-address>\n  opencircuit classify-cidr <ipv4-cidr>\n  opencircuit summary <ipv4-cidr>\n  opencircuit masks <ipv4-cidr>\n  opencircuit range <ipv4-cidr>\n  opencircuit overlap <ipv4-cidr-a> <ipv4-cidr-b>\n  opencircuit relation <ipv4-cidr-a> <ipv4-cidr-b>\n  opencircuit scan <ipv4-cidr>"));
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
fn usable_command_outputs_true_for_valid_host() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["usable", "192.168.1.0/24", "192.168.1.10"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "true\n");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

#[test]
fn usable_command_outputs_false_for_network_and_broadcast() {
    let network = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["usable", "192.168.1.0/24", "192.168.1.0"])
        .output()
        .expect("failed to run opencircuit binary");
    let broadcast = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["usable", "192.168.1.0/24", "192.168.1.255"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(network.status.success());
    assert_eq!(String::from_utf8_lossy(&network.stdout), "false\n");
    assert!(broadcast.status.success());
    assert_eq!(String::from_utf8_lossy(&broadcast.stdout), "false\n");
}

#[test]
fn usable_command_handles_31_as_usable_endpoints() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["usable", "10.0.0.0/31", "10.0.0.0"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "true\n");
}

#[test]
fn usable_command_fails_for_invalid_ip_argument() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["usable", "192.168.1.0/24", "nope"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Invalid IPv4 address"));
}

#[test]
fn next_command_outputs_next_ipv4() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["next", "192.168.1.42"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "192.168.1.43\n");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

#[test]
fn next_command_fails_on_upper_boundary() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["next", "255.255.255.255"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr).contains("No next IPv4 address"));
}

#[test]
fn prev_command_outputs_previous_ipv4() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["prev", "192.168.1.42"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "192.168.1.41\n");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

#[test]
fn prev_command_fails_on_lower_boundary() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["prev", "0.0.0.0"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr).contains("No previous IPv4 address"));
}

#[test]
fn next_prev_commands_fail_for_invalid_ip() {
    let next = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["next", "nope"])
        .output()
        .expect("failed to run opencircuit binary");
    let prev = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["prev", "nope"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!next.status.success());
    assert!(String::from_utf8_lossy(&next.stderr).contains("Invalid IPv4 address"));
    assert!(!prev.status.success());
    assert!(String::from_utf8_lossy(&prev.stderr).contains("Invalid IPv4 address"));
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
fn classify_cidr_command_outputs_expected_network_flags() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["classify-cidr", "192.168.1.42/24"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "cidr=192.168.1.0/24\nnetwork=192.168.1.0\nbroadcast=192.168.1.255\nprivate=true\nlink_local=false\nloopback=false\nmulticast=false\n"
    );
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

#[test]
fn classify_cidr_command_handles_multicast_networks() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["classify-cidr", "224.0.0.1/24"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("multicast=true"));
    assert!(String::from_utf8_lossy(&output.stdout).contains("private=false"));
}

#[test]
fn classify_cidr_command_fails_for_invalid_cidr() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["classify-cidr", "bad/24"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Invalid CIDR"));
}

#[test]
fn classify_cidr_command_fails_with_missing_argument() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .arg("classify-cidr")
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("Usage:\n  opencircuit normalize <ipv4-cidr>\n  opencircuit info <ipv4-cidr>\n  opencircuit contains <ipv4-cidr> <ipv4-address>\n  opencircuit usable <ipv4-cidr> <ipv4-address>\n  opencircuit next <ipv4-address>\n  opencircuit prev <ipv4-address>\n  opencircuit classify <ipv4-address>\n  opencircuit classify-cidr <ipv4-cidr>\n  opencircuit summary <ipv4-cidr>\n  opencircuit masks <ipv4-cidr>\n  opencircuit range <ipv4-cidr>\n  opencircuit overlap <ipv4-cidr-a> <ipv4-cidr-b>\n  opencircuit relation <ipv4-cidr-a> <ipv4-cidr-b>\n  opencircuit scan <ipv4-cidr>"));
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

#[test]
fn masks_command_outputs_prefix_and_masks() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["masks", "192.168.1.42/24"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "cidr=192.168.1.0/24\nprefix=24\nsubnet_mask=255.255.255.0\nwildcard_mask=0.0.0.255\n"
    );
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

#[test]
fn masks_command_fails_for_invalid_cidr() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["masks", "bad/24"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Invalid CIDR"));
}

#[test]
fn masks_command_fails_with_missing_argument() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .arg("masks")
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("Usage:\n  opencircuit normalize <ipv4-cidr>\n  opencircuit info <ipv4-cidr>\n  opencircuit contains <ipv4-cidr> <ipv4-address>\n  opencircuit usable <ipv4-cidr> <ipv4-address>\n  opencircuit next <ipv4-address>\n  opencircuit prev <ipv4-address>\n  opencircuit classify <ipv4-address>\n  opencircuit classify-cidr <ipv4-cidr>\n  opencircuit summary <ipv4-cidr>\n  opencircuit masks <ipv4-cidr>\n  opencircuit range <ipv4-cidr>\n  opencircuit overlap <ipv4-cidr-a> <ipv4-cidr-b>\n  opencircuit relation <ipv4-cidr-a> <ipv4-cidr-b>\n  opencircuit scan <ipv4-cidr>"));
}

#[test]
fn range_command_outputs_usable_host_range() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["range", "192.168.1.42/24"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "cidr=192.168.1.0/24\nfirst=192.168.1.1\nlast=192.168.1.254\nusable=254\n"
    );
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

#[test]
fn range_command_fails_for_invalid_cidr() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["range", "nope/24"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Invalid CIDR"));
}

#[test]
fn range_command_fails_with_missing_argument() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .arg("range")
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("Usage:\n  opencircuit normalize <ipv4-cidr>\n  opencircuit info <ipv4-cidr>\n  opencircuit contains <ipv4-cidr> <ipv4-address>\n  opencircuit usable <ipv4-cidr> <ipv4-address>\n  opencircuit next <ipv4-address>\n  opencircuit prev <ipv4-address>\n  opencircuit classify <ipv4-address>\n  opencircuit classify-cidr <ipv4-cidr>\n  opencircuit summary <ipv4-cidr>\n  opencircuit masks <ipv4-cidr>\n  opencircuit range <ipv4-cidr>\n  opencircuit overlap <ipv4-cidr-a> <ipv4-cidr-b>\n  opencircuit relation <ipv4-cidr-a> <ipv4-cidr-b>\n  opencircuit scan <ipv4-cidr>"));
}

#[test]
fn overlap_command_outputs_true_for_overlapping_cidrs() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["overlap", "192.168.1.0/24", "192.168.1.128/25"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "true\n");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

#[test]
fn overlap_command_outputs_false_for_disjoint_cidrs() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["overlap", "192.168.1.0/24", "192.168.2.0/24"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "false\n");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

#[test]
fn overlap_command_fails_for_invalid_cidr() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["overlap", "bad/24", "192.168.1.0/24"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Invalid CIDR"));
}

#[test]
fn overlap_command_fails_with_missing_argument() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["overlap", "192.168.1.0/24"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("Usage:\n  opencircuit normalize <ipv4-cidr>\n  opencircuit info <ipv4-cidr>\n  opencircuit contains <ipv4-cidr> <ipv4-address>\n  opencircuit usable <ipv4-cidr> <ipv4-address>\n  opencircuit next <ipv4-address>\n  opencircuit prev <ipv4-address>\n  opencircuit classify <ipv4-address>\n  opencircuit classify-cidr <ipv4-cidr>\n  opencircuit summary <ipv4-cidr>\n  opencircuit masks <ipv4-cidr>\n  opencircuit range <ipv4-cidr>\n  opencircuit overlap <ipv4-cidr-a> <ipv4-cidr-b>\n  opencircuit relation <ipv4-cidr-a> <ipv4-cidr-b>\n  opencircuit scan <ipv4-cidr>"));
}

#[test]
fn relation_command_reports_equal() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["relation", "192.168.1.0/24", "192.168.1.0/24"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "equal\n");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

#[test]
fn relation_command_reports_a_contains_b() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["relation", "192.168.1.0/24", "192.168.1.128/25"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "a_contains_b\n");
}

#[test]
fn relation_command_reports_b_contains_a() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["relation", "192.168.1.128/25", "192.168.1.0/24"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "b_contains_a\n");
}

#[test]
fn relation_command_normalizes_inputs_before_comparison() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["relation", "192.168.1.42/24", "192.168.1.130/25"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "a_contains_b\n");
}

#[test]
fn relation_command_reports_disjoint() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["relation", "192.168.1.0/24", "192.168.2.0/24"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "disjoint\n");
}

#[test]
fn relation_command_fails_for_invalid_cidr() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["relation", "bad/24", "192.168.1.0/24"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Invalid CIDR"));
}

#[test]
fn relation_command_fails_with_missing_argument() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["relation", "192.168.1.0/24"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("Usage:\n  opencircuit normalize <ipv4-cidr>\n  opencircuit info <ipv4-cidr>\n  opencircuit contains <ipv4-cidr> <ipv4-address>\n  opencircuit usable <ipv4-cidr> <ipv4-address>\n  opencircuit next <ipv4-address>\n  opencircuit prev <ipv4-address>\n  opencircuit classify <ipv4-address>\n  opencircuit classify-cidr <ipv4-cidr>\n  opencircuit summary <ipv4-cidr>\n  opencircuit masks <ipv4-cidr>\n  opencircuit range <ipv4-cidr>\n  opencircuit overlap <ipv4-cidr-a> <ipv4-cidr-b>\n  opencircuit relation <ipv4-cidr-a> <ipv4-cidr-b>\n  opencircuit scan <ipv4-cidr>"));
}

#[test]
fn scan_command_outputs_header_and_records() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["scan", "127.0.0.0/30"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("scanned_hosts="));
    assert!(stdout.contains("records="));
    assert!(stdout.contains("shown="));
    assert!(stdout.contains("elapsed_ms="));
    assert!(stdout.contains("ip=127.0.0.1"));
    assert!(stdout.contains("ip=127.0.0.2"));
    assert!(stdout.contains("hostname_source="));
    assert!(String::from_utf8_lossy(&output.stderr).contains("[scan] probing"));
}

#[test]
fn scan_command_defaults_to_showing_only_up_hosts() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["scan", "192.168.1.0/30"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("shown=0") || stdout.contains("shown=1") || stdout.contains("shown=2"));
    assert!(!stdout.contains("status=down"));
}

#[test]
fn scan_command_all_flag_keeps_backward_compatible_behavior() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["scan", "192.168.1.0/30", "--all"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("shown=2"));
    assert!(stdout.contains("ip=192.168.1.1"));
    assert!(stdout.contains("ip=192.168.1.2"));
}

#[test]
fn scan_command_rejects_unknown_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["scan", "192.168.1.0/30", "--verbose"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Usage:"));
}

#[test]
fn scan_command_supports_no_dns_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["scan", "127.0.0.0/30", "--no-dns"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("scanned_hosts="));
    assert!(stdout.contains("shown="));
}

#[test]
fn scan_command_accepts_custom_scan_tuning_flags() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args([
            "scan",
            "127.0.0.0/30",
            "--ports",
            "22,80",
            "--timeout-ms",
            "200",
            "--concurrency",
            "4",
            "--no-dns",
        ])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("scanned_hosts="));
}

#[test]
fn scan_command_accepts_explicit_fast_profile() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["scan", "127.0.0.0/30", "--fast", "--no-dns"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("scanned_hosts="));
}

#[test]
fn scan_command_rejects_multiple_profiles() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["scan", "127.0.0.0/30", "--fast", "--deep"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Only one scan profile can be selected")
    );
}

#[test]
fn scan_command_rejects_invalid_ports_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["scan", "127.0.0.0/30", "--ports", "22,abc"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Invalid --ports list"));
}

#[test]
fn scan_command_rejects_invalid_timeout_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["scan", "127.0.0.0/30", "--timeout-ms", "0"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--timeout-ms must be greater than zero")
    );
}

#[test]
fn scan_command_rejects_invalid_concurrency_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["scan", "127.0.0.0/30", "--concurrency", "0"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--concurrency must be greater than zero")
    );
}

#[test]
fn scan_command_fails_for_invalid_cidr() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["scan", "bad/24"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Scan failed"));
}

#[test]
fn scan_command_fails_when_target_exceeds_limit() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["scan", "10.0.0.0/16"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Scan failed"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("exceeds allowed limit"));
}

#[test]
fn scan_command_fails_with_missing_argument() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .arg("scan")
        .output()
        .expect("failed to run opencircuit binary");

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("Usage:\n  opencircuit normalize <ipv4-cidr>\n  opencircuit info <ipv4-cidr>\n  opencircuit contains <ipv4-cidr> <ipv4-address>\n  opencircuit usable <ipv4-cidr> <ipv4-address>\n  opencircuit next <ipv4-address>\n  opencircuit prev <ipv4-address>\n  opencircuit classify <ipv4-address>\n  opencircuit classify-cidr <ipv4-cidr>\n  opencircuit summary <ipv4-cidr>\n  opencircuit masks <ipv4-cidr>\n  opencircuit range <ipv4-cidr>\n  opencircuit overlap <ipv4-cidr-a> <ipv4-cidr-b>\n  opencircuit relation <ipv4-cidr-a> <ipv4-cidr-b>\n  opencircuit scan <ipv4-cidr>"));
}
