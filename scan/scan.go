package scan

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type progressCallback func(ip string)

type Device struct {
	IP       string
	Status   string // "up", "recently_seen"
	Hostname string
	Ports    []int
}

var (
	defaultPorts = []int{22, 53, 80, 139, 443, 445, 554, 631, 8008, 8009, 8080, 8443, 8888, 62078}
	timeout      = 500 * time.Millisecond
)


func Run(cidr string,progressCB progressCallback) ([]Device, error) {

	hosts, err := expandHosts(cidr)
	if err != nil {
		return nil, err
	}

	for _,h := range hosts {
		fmt.Printf("Scanning %s\n", h)
	}

	if len(hosts) == 0 {
		return nil, fmt.Errorf("no hosts to scan")
	}

	neighborIPs := loadNeighborTable()
	dhcpHosts := loadDHCPLeases()

	var wg sync.WaitGroup
	results := make(chan Device, len(hosts))
	sem := make(chan struct{}, 64)

	for _, ip := range hosts {
		wg.Add(1)
		sem <- struct{}{}

		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			if progressCB != nil {
				progressCB(ip)
			}
			device := probeHost(ip, neighborIPs, dhcpHosts)
			if device.Status != "" {
				results <- device
			}
		}(ip)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var devices []Device
	for d := range results {
		devices = append(devices, d)
	}

	return devices, nil
}

func expandHosts(cidrStr string) ([]string, error) {
	_, network, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %s", cidrStr)
	}

	mask := network.Mask
	prefix := 0
	for _, b := range mask {
		prefix += bitsSet(b)
	}

	networkIP := network.IP.To4()
	networkNum := ipToUint32(networkIP)
	broadcastNum := networkNum | (^ipToUint32(net.IP(mask)))

	var hosts []string

	// Handle special cases
	if prefix == 32 {
		return []string{networkIP.String()}, nil
	}
	if prefix == 31 {
		return []string{uint32ToIP(networkNum).String(), uint32ToIP(broadcastNum).String()}, nil
	}

	for i := networkNum + 1; i < broadcastNum; i++ {
		hosts = append(hosts, uint32ToIP(i).String())
	}

	return hosts, nil
}

func bitsSet(b byte) int {
	count := 0
	for b > 0 {
		count++
		b &= b - 1
	}
	return count
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(n uint32) net.IP {
	ip := net.IP{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	return ip.To4()
}

func probeHost(ip string, neighborIPs map[string]bool, dhcpHosts map[string]string) Device {
	device := Device{IP: ip}

	// Check neighbor table first (fastest)
	if neighborIPs[ip] {
		device.Status = "up"
		device.Ports = []int{}
		return device
	}

	// Check DHCP leases
	if hostname, ok := dhcpHosts[ip]; ok {
		device.Status = "recently_seen"
		device.Hostname = hostname
		device.Ports = []int{}
		return device
	}

	// TCP probe common ports
	for _, port := range defaultPorts {
		addr := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err == nil {
			conn.Close()
			device.Status = "up"
			device.Ports = append(device.Ports, port)
		}
	}

	// Try ping as fallback
	if device.Status == "" {
		if ping(ip) {
			device.Status = "up"
		}
	}

	// Try reverse DNS
	if device.Status == "up" {
		names, err := net.LookupAddr(ip)
		if err == nil && len(names) > 0 {
			device.Hostname = strings.TrimSuffix(names[0], ".")
		}
	}

	if device.Status == "" {
		device.Status = ""
	}

	return device
}

func ping(host string) bool {
	cmd := exec.Command("ping", "-c", "1", "-W", "1", host)
	return cmd.Run() == nil
}

func loadNeighborTable() map[string]bool {
	result := make(map[string]bool)

	cmd := exec.Command("ip", "neigh")
	output, err := cmd.Output()
	if err != nil {
		return result
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			ip := fields[0]
			if net.ParseIP(ip) != nil {
				result[ip] = true
			}
		}
	}

	return result
}

func loadDHCPLeases() map[string]string {
	result := make(map[string]string)

	paths := []string{
		"/var/lib/misc/dnsmasq.leases",
		"/tmp/dhcp.leases",
		"/tmp/udhcpd.leases",
	}

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				ip := fields[2]
				hostname := fields[3]
				if hostname != "*" && net.ParseIP(ip) != nil {
					result[ip] = hostname
				}
			}
		}
	}

	return result
}
