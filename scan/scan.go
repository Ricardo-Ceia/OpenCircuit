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

	// Always add localhost if in range (common case)
	hostsMap := make(map[string]bool)
	for _, h := range hosts {
		hostsMap[h] = true
	}
	if hostsMap["127.0.0.1"] {
		deviceMap["127.0.0.1"] = Device{IP: "127.0.0.1", Status: "up"}
	}

	// Get devices from ARP table (ip neigh)
	for device := range scanARPTable(hosts) {
		deviceMap[device.IP] = device
	}

	// mDNS scan for hostnames
	for device := range mDNSScan() {
		if existing, ok := deviceMap[device.IP]; ok {
			if device.Hostname != "" {
				existing.Hostname = device.Hostname
			}
			deviceMap[device.IP] = existing
		} else {
			deviceMap[device.IP] = device
		}
	}

	// Parallel host probing with semaphore
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 32) // 32 concurrent workers

	for _, ip := range hosts {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if progressCB != nil {
				progressCB(ip)
			}

			device := probeHost(ip)

			httpInfo := probeHTTP(ip)
			if httpInfo.Server != "" {
				device.HTTPInfo = httpInfo.Server
				if httpInfo.Title != "" {
					device.HTTPInfo += " - " + httpInfo.Title
				}
			}

			upnpInfo := probeUPnP(ip)
			if upnpInfo.FriendlyName != "" {
				device.UPnPInfo = upnpInfo.FriendlyName
			}

			mdnsInfo := probeMDNSService(ip)
			if mdnsInfo.Service != "" {
				device.Services = append(device.Services, mdnsInfo.Service)
				if mdnsInfo.Name != "" {
					device.FriendlyName = mdnsInfo.Name
				}
			}

			device.FriendlyName = buildFriendlyName(device)

			mu.Lock()
			if device.Status != "" {
				if existing, ok := deviceMap[ip]; ok {
					existing.Status = device.Status
					existing.Ports = device.Ports
					if device.Hostname != "" {
						existing.Hostname = device.Hostname
					}
					if device.FriendlyName != "" {
						existing.FriendlyName = device.FriendlyName
					}
					if device.HTTPInfo != "" {
						existing.HTTPInfo = device.HTTPInfo
					}
					if device.UPnPInfo != "" {
						existing.UPnPInfo = device.UPnPInfo
					}
					if len(device.Services) > 0 {
						existing.Services = device.Services
					}
					deviceMap[ip] = existing
				} else {
					deviceMap[ip] = device
				}
			}
			mu.Unlock()
		}(ip)
	}

	wg.Wait()

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

	// Try reverse DNS (always, even if no ports open)
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		device.Hostname = strings.TrimSuffix(names[0], ".")
	}

	return device
}

// scanARPTable reads the ARP table using 'ip neigh' command
// Returns devices with MAC addresses and vendor info
func scanARPTable(hosts []string) chan Device {
	results := make(chan Device, 256)

	go func() {
		defer close(results)

		// Trigger ARP entries by sending UDP packets to common ports
		ports := []int{80, 443, 53, 123, 161}
		for _, ip := range hosts {
			for _, port := range ports {
				addr := fmt.Sprintf("%s:%d", ip, port)
				conn, err := net.DialTimeout("udp", addr, 100*time.Millisecond)
				if err == nil {
					conn.Close()
				}
			}
			time.Sleep(5 * time.Millisecond)
		}

		// Read ARP table
		cmd := exec.Command("ip", "neigh")
		output, err := cmd.Output()
		if err != nil {
			return
		}

		hostsMap := make(map[string]bool)
		for _, h := range hosts {
			hostsMap[h] = true
		}

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				ip := fields[0]
				if hostsMap[ip] && net.ParseIP(ip) != nil {
					mac := ""
					for i, f := range fields {
						if f == "lladdr" && i+1 < len(fields) {
							mac = fields[i+1]
							break
						}
					}
					if mac != "" {
						vendor := MACVendorLookup(mac)
						device := Device{
							IP:     ip,
							Status: "up",
							MAC:    mac,
							Vendor: vendor,
						}
						select {
						case results <- device:
						default:
						}
					}
				}
			}
		}
	}()

	return results
}

// mDNSScan discovers devices using mDNS (Multicast DNS)
func mDNSScan() chan Device {
	results := make(chan Device, 256)

	go func() {
		defer close(results)

		mdnsAddr := &net.UDPAddr{
			IP:   net.IP{224, 0, 0, 251},
			Port: 5353,
		}

		conn, err := net.ListenMulticastUDP("udp4", nil, mdnsAddr)
		if err != nil {
			return
		}
		defer conn.Close()

		conn.SetReadDeadline(time.Now().Add(2 * time.Second))

		query := []byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}

		for i := 0; i < 3; i++ {
			conn.WriteToUDP(query, mdnsAddr)
			time.Sleep(100 * time.Millisecond)
		}

		seen := make(map[string]bool)
		buffer := make([]byte, 65536)
		for {
			n, addr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				break
			}
			if n > 0 {
				ip := addr.IP.String()
				if isValidIP(ip) && !seen[ip] {
					seen[ip] = true
					hostname := parseMdnsHostname(buffer[:n])
					device := Device{
						IP:       ip,
						Status:   "up",
						Hostname: hostname,
					}
					select {
					case results <- device:
					default:
					}
				}
			}
		}
	}()

	return results
}

func parseMdnsHostname(data []byte) string {
	str := string(data)
	for _, line := range strings.Split(str, "\n") {
		if strings.Contains(line, " PTR ") && strings.HasSuffix(line, ".local") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				name := parts[3]
				name = strings.TrimSuffix(name, ".")
				name = strings.TrimSuffix(name, ".local")
				if name != "" && !strings.Contains(name, ".in-addr.arpa") {
					return name
				}
			}
		}
	}
	return ""
}

func isValidIP(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() != nil
}
