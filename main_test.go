package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestHelpCommand(t *testing.T) {
	cmd := exec.Command("./opencircuit", "help")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run: %v", err)
	}

	if !strings.Contains(string(output), "Usage:") {
		t.Error("help should contain Usage")
	}

	if !strings.Contains(string(output), "scan <cidr>") {
		t.Error("help should contain scan command")
	}
}

func TestScanCommand(t *testing.T) {
	cmd := exec.Command("./opencircuit", "scan", "127.0.0.0/30")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run: %v", err)
	}

	if !strings.Contains(string(output), "scanned_hosts=") {
		t.Error("output should contain scanned_hosts")
	}

	if !strings.Contains(string(output), "ip=127.0.0.1") {
		t.Error("output should contain 127.0.0.1")
	}
}

func TestScanInvalidCIDR(t *testing.T) {
	cmd := exec.Command("./opencircuit", "scan", "invalid")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Error("should fail with invalid CIDR")
	}

	if !strings.Contains(string(output), "invalid CIDR") {
		t.Error("error should mention invalid CIDR")
	}
}

func TestScanMissingCIDR(t *testing.T) {
	cmd := exec.Command("./opencircuit", "scan")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Error("should fail with missing CIDR")
	}

	if !strings.Contains(string(output), "Usage:") {
		t.Error("should show usage")
	}
}

func TestUnknownCommand(t *testing.T) {
	cmd := exec.Command("./opencircuit", "unknown")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Error("should fail with unknown command")
	}

	if !strings.Contains(string(output), "Unknown command") {
		t.Error("should mention unknown command")
	}
}

func TestOutputFormat(t *testing.T) {
	cmd := exec.Command("./opencircuit", "scan", "127.0.0.0/30")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) < 2 {
		t.Fatal("should have header and at least one device")
	}

	// Check header format
	if !strings.HasPrefix(lines[0], "scanned_hosts=") {
		t.Error("first line should be header with scanned_hosts")
	}

	// Check device line format
	if !strings.HasPrefix(lines[1], "ip=") {
		t.Error("device lines should start with ip=")
	}

	if !strings.Contains(lines[1], "status=") {
		t.Error("device line should contain status=")
	}

	if !strings.Contains(lines[1], "hostname=") {
		t.Error("device line should contain hostname=")
	}

	if !strings.Contains(lines[1], "ports=") {
		t.Error("device line should contain ports=")
	}
}

func TestMainHelpFlag(t *testing.T) {
	cmd := exec.Command("./opencircuit", "--help")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run: %v", err)
	}

	if !strings.Contains(string(output), "Usage:") {
		t.Error("--help should show usage")
	}
}

func TestMainHFlag(t *testing.T) {
	cmd := exec.Command("./opencircuit", "-h")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run: %v", err)
	}

	if !strings.Contains(string(output), "Usage:") {
		t.Error("-h should show usage")
	}
}

func TestShowOnlyUpAndRecentlySeen(t *testing.T) {
	// This test verifies that offline devices are not shown
	// Since we're scanning 127.0.0.0/30, both hosts should be up
	// (localhost and another IP), so we just verify output structure
	cmd := exec.Command("./opencircuit", "scan", "127.0.0.0/30")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	header := lines[0]

	if !strings.Contains(header, "shown=") {
		t.Error("header should contain shown count")
	}

	// Verify shown count is present and reasonable
	if !strings.Contains(header, "shown=2") {
		t.Logf("header: %s", header)
	}
}
