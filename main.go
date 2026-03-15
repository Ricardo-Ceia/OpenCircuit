package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"opencircuit/scan"
)

const USAGE = `OpenCircuit - Simple Home Network Discovery

Usage:
  opencircuit scan <cidr>       Scan network for devices
  opencircuit help             Show this help
  opencircuit --help           Show this help

Examples:
  opencircuit scan 192.168.1.0/24
  opencircuit scan 10.0.0.0/8
`

func main() {
	flag.Usage = func() {
		fmt.Print(USAGE)
	}

	flag.Parse()

	args := flag.Args()
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
	devices, err := scan.Run(cidr,func (ip string) {
		fmt.Fprintf(os.Stderr, "Scanning %s...\n", ip)	
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	
	// Filter: show only "up" and "recently_seen"
	filtered := []scan.Device{}
	for _, d := range devices {
		if d.Status == "up" || d.Status == "recently_seen" {
			filtered = append(filtered, d)
		}
	}

	fmt.Printf("scanned_hosts=%d shown=%d\n", len(devices), len(filtered))

	for _, d := range filtered {
		hostname := d.Hostname
		if hostname == "" {
			hostname = "-"
		}
		ports := "-"
		if len(d.Ports) > 0 {
			ports = intsToString(d.Ports)
		}
		fmt.Printf("ip=%s status=%s hostname=%s ports=%s\n",
			d.IP, d.Status, hostname, ports)
	}
}

func intsToString(ports []int) string {
	strs := make([]string, len(ports))
	for i, p := range ports {
		strs[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(strs, ",")
}
