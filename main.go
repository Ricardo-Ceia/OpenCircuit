package main

import (
	"fmt"
	"os"
	"strings"

	"opencircuit/scan"

	"github.com/spf13/pflag"
)

const USAGE = `OpenCircuit - Simple Home Network Discovery

Usage:
  opencircuit scan <cidr>       Scan network for devices
  opencircuit --quiet scan <cidr>  Scan without progress
  opencircuit help             Show this help
  opencircuit --help           Show this help

Examples:
  opencircuit scan 192.168.1.0/24
  opencircuit scan 10.0.0.0/8
`

var quietFlag bool

func init() {
	pflag.BoolVarP(&quietFlag, "quiet", "q", false, "suppress progress output")
	pflag.Usage = func() {
		fmt.Print(USAGE)
	}
}

func main() {
	pflag.Parse()

	args := pflag.Args()
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, USAGE)
		os.Exit(1)
	}

	switch args[0] {
	case "help", "--help", "-h":
		fmt.Print(USAGE)
	case "scan":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: opencircuit scan <cidr>")
			os.Exit(1)
		}
		runScan(args[1])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n%s\n", args[0], USAGE)
		os.Exit(1)
	}
}

func runScan(cidr string) {
	devices, err := scan.Run(cidr, func(ip string) {
		if !quietFlag {
			fmt.Fprintf(os.Stderr, "Scanning %s...\n", ip)
		}
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	filtered := []scan.Device{}
	for _, d := range devices {
		if d.Status == "up" || d.Status == "recently_seen" {
			filtered = append(filtered, d)
		}
	}

	fmt.Printf("\nFound %d devices:\n\n", len(filtered))

	for _, d := range filtered {
		fmt.Printf("✓ %s\n", d.DisplayName())
		fmt.Printf("  IP: %s\n", d.IP)

		if d.MAC != "" {
			fmt.Printf("  MAC: %s\n", d.MAC)
		}

		if d.Services != nil && len(d.Services) > 0 {
			fmt.Printf("  Services: %s\n", strings.Join(d.Services, ", "))
		}

		if len(d.Ports) > 0 {
			fmt.Printf("  Ports: %s\n", intsToString(d.Ports))
		}

		fmt.Println()
	}
}

func intsToString(ports []int) string {
	strs := make([]string, len(ports))
	for i, p := range ports {
		strs[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(strs, ",")
}
