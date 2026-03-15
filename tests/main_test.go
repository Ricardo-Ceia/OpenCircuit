package tests

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runCmd(args ...string) *exec.Cmd {
	return exec.Command("./opencircuit", args...)
}

func TestHelpCommand(t *testing.T) {
	cmd := runCmd("help")
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run: %v, output: %s", err, string(output))
	}

	if !strings.Contains(string(output), "Usage:") {
		t.Error("help should contain Usage")
	}

	if !strings.Contains(string(output), "scan <cidr>") {
		t.Error("help should contain scan command")
	}
}

func TestScanCommand(t *testing.T) {
	cmd := runCmd("scan", "127.0.0.0/30")
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run: %v, output: %s", err, string(output))
	}

	if !strings.Contains(string(output), "scanned_hosts=") {
		t.Error("output should contain scanned_hosts")
	}

	if !strings.Contains(string(output), "ip=127.0.0.1") {
		t.Error("output should contain 127.0.0.1")
	}
}

func TestScanInvalidCIDR(t *testing.T) {
	cmd := runCmd("scan", "invalid")
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Error("should fail with invalid CIDR")
	}

	if !strings.Contains(string(output), "invalid CIDR") {
		t.Logf("output: %s", string(output))
		t.Error("error should mention invalid CIDR")
	}
}

func TestScanMissingCIDR(t *testing.T) {
	cmd := runCmd("scan")
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Error("should fail with missing CIDR")
	}

	if !strings.Contains(string(output), "Usage:") {
		t.Error("should show usage")
	}
}

func TestUnknownCommand(t *testing.T) {
	cmd := runCmd("unknown")
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Error("should fail with unknown command")
	}

	if !strings.Contains(string(output), "Unknown command") {
		t.Error("should mention unknown command")
	}
}

func TestOutputFormat(t *testing.T) {
	cmd := runCmd("scan", "127.0.0.0/30")
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run: %v, output: %s", err, string(output))
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
	cmd := runCmd("--help")
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run: %v, output: %s", err, string(output))
	}

	if !strings.Contains(string(output), "Usage:") {
		t.Error("--help should show usage")
	}
}

func TestMainHFlag(t *testing.T) {
	cmd := runCmd("-h")
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run: %v, output: %s", err, string(output))
	}

	if !strings.Contains(string(output), "Usage:") {
		t.Error("-h should show usage")
	}
}

func TestShowOnlyUpAndRecentlySeen(t *testing.T) {
	cmd := runCmd("scan", "127.0.0.0/30")
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run: %v, output: %s", err, string(output))
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	header := lines[0]

	if !strings.Contains(header, "shown=") {
		t.Error("header should contain shown count")
	}
}

// GetProjectRoot returns the absolute path to the project root
func GetProjectRoot() string {
	dir, _ := filepath.Abs("..")
	return dir
}
