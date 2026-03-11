use std::process::Command;

#[test]
fn scan_progress_output_no_longer_contains_raw_ping_lines() {
    let output = Command::new(env!("CARGO_BIN_EXE_opencircuit"))
        .args(["scan", "127.0.0.0/30", "--no-dns"])
        .output()
        .expect("failed to run opencircuit binary");

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(stderr.contains("[scan] probing"));
    assert!(!stderr.contains("PING "));
    assert!(!stderr.contains("ping statistics"));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("scanned_hosts="));
    assert!(stdout.contains("records="));
}
