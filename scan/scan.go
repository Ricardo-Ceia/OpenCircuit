package scan

import (
	"fmt"
	"net"
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

func Run(cidr string, progressCB progressCallback) ([]Device, error) {
	hosts, err := expandHosts(cidr)
	if err != nil {
		return nil, err
	}

	if len(hosts) == 0 {
		return nil, fmt.Errorf("no hosts to scan")
	}

	deviceMap := make(map[string]Device)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Quick: Check ARP neighbor table first (fastest)
	// Only include neighbors that are in our scan range
	neighborIPs := loadNeighborTable()
	hostsMap := make(map[string]bool)
	for _, h := range hosts {
		hostsMap[h] = true
	}
	for ip := range neighborIPs {
		if hostsMap[ip] {
			mu.Lock()
			if _, exists := deviceMap[ip]; !exists {
				deviceMap[ip] = Device{IP: ip, Status: "recently_seen"}
			}
			mu.Unlock()
		}
	}

	// Always add localhost if in range (common case)
	if hostsMap["127.0.0.1"] {
		mu.Lock()
		if _, exists := deviceMap["127.0.0.1"]; !exists {
			deviceMap["127.0.0.1"] = Device{IP: "127.0.0.1", Status: "up"}
		}
		mu.Unlock()
	}

	// Run discovery methods in parallel
	// Method 1: ARP scan (probes to populate neighbor cache)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ip := range arpScan(hosts) {
			mu.Lock()
			if existing, ok := deviceMap[ip]; ok {
				existing.Status = "up"
				deviceMap[ip] = existing
			} else {
				deviceMap[ip] = Device{IP: ip, Status: "up"}
			}
			mu.Unlock()
		}
	}()

	// Method 2: mDNS scan (finds Apple devices, Chromecast, etc)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ip := range mDNSScan() {
			mu.Lock()
			if existing, ok := deviceMap[ip]; ok {
				existing.Status = "up"
				deviceMap[ip] = existing
			} else {
				deviceMap[ip] = Device{IP: ip, Status: "up"}
			}
			mu.Unlock()
		}
	}()

	// Method 3: SSDP scan (finds TVs, consoles, routers)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ip := range ssdpScan() {
			mu.Lock()
			if existing, ok := deviceMap[ip]; ok {
				existing.Status = "up"
				deviceMap[ip] = existing
			} else {
				deviceMap[ip] = Device{IP: ip, Status: "up"}
			}
			mu.Unlock()
		}
	}()

	// Method 4: TCP probe (finds devices with open ports)
	wg.Add(1)
	go func() {
		defer wg.Done()
		sem := make(chan struct{}, 64)
		var probeWg sync.WaitGroup

		for _, ip := range hosts {
			probeWg.Add(1)
			sem <- struct{}{}

			go func(ip string) {
				defer probeWg.Done()
				defer func() { <-sem }()

				if progressCB != nil {
					progressCB(ip)
				}

				device := probeHost(ip)
				if device.Status != "" {
					mu.Lock()
					if existing, ok := deviceMap[ip]; ok {
						existing.Status = device.Status
						existing.Ports = device.Ports
						if device.Hostname != "" {
							existing.Hostname = device.Hostname
						}
						deviceMap[ip] = existing
					} else {
						deviceMap[ip] = device
					}
					mu.Unlock()
				}
			}(ip)
		}

		probeWg.Wait()
	}()

	wg.Wait()

	// Final fallback: ICMP ping sweep if no devices found
	mu.Lock()
	if len(deviceMap) == 0 {
		for _, ip := range hosts {
			if ping(ip) {
				deviceMap[ip] = Device{IP: ip, Status: "up"}
			}
		}
	}
	mu.Unlock()

	// Convert map to slice
	var devices []Device
	for _, d := range deviceMap {
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

func probeHost(ip string) Device {
	device := Device{IP: ip}

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

	// Try ICMP ping as fallback
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

	return device
}

func ping(host string) bool {
	conn, err := net.DialTimeout("icmp", host, timeout)
	if err == nil {
		conn.Close()
		return true
	}
	return false
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
