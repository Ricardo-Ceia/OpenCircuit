package scan

import (
	"net"
	"os/exec"
	"strings"
	"time"
)

// arpScan discovers devices by probing all hosts in the subnet
// Uses UDP probes to trigger ARP cache entries
func arpScan(hosts []string) chan string {
	results := make(chan string, 256)

	go func() {
		defer close(results)

		for _, ip := range hosts {
			// Send UDP probe to trigger ARP cache entry
			conn, err := net.DialTimeout("udp4", ip+":9999", 100*time.Millisecond)
			if err == nil {
				conn.Close()
			}
			time.Sleep(10 * time.Millisecond)

			// Check if IP is now in neighbor table
			if inNeighborTable(ip) {
				select {
				case results <- ip:
				default:
				}
			}
		}
	}()

	return results
}

// inNeighborTable checks if an IP is in the ARP neighbor table
func inNeighborTable(ip string) bool {
	cmd := exec.Command("ip", "neigh")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), ip)
}

// mDNSScan discovers devices using mDNS (Multicast DNS)
// This finds Apple devices, Chromecasts, smart speakers, printers, etc.
func mDNSScan() chan string {
	results := make(chan string, 256)

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

		query := buildMDNSQuery()
		for i := 0; i < 3; i++ {
			conn.WriteToUDP(query, mdnsAddr)
			time.Sleep(100 * time.Millisecond)
		}

		buffer := make([]byte, 65536)
		for {
			n, addr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				break
			}
			if n > 0 {
				ip := addr.IP.String()
				if isValidIP(ip) {
					select {
					case results <- ip:
					default:
					}
				}
			}
		}
	}()

	return results
}

func buildMDNSQuery() []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

// ssdpScan discovers devices using SSDP (Simple Service Discovery Protocol)
// This finds TVs, Xbox, PlayStation, routers, smart home devices
func ssdpScan() chan string {
	results := make(chan string, 256)

	go func() {
		defer close(results)

		ssdpAddr := &net.UDPAddr{
			IP:   net.IP{239, 255, 255, 250},
			Port: 1900,
		}

		conn, err := net.ListenMulticastUDP("udp4", nil, ssdpAddr)
		if err != nil {
			return
		}
		defer conn.Close()

		conn.SetReadDeadline(time.Now().Add(2 * time.Second))

		query := buildSSDPQuery()
		for i := 0; i < 3; i++ {
			conn.WriteToUDP(query, ssdpAddr)
			time.Sleep(100 * time.Millisecond)
		}

		buffer := make([]byte, 65536)
		for {
			n, addr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				break
			}
			if n > 0 {
				ip := addr.IP.String()
				if isValidIP(ip) {
					select {
					case results <- ip:
					default:
					}
				}
			}
		}
	}()

	return results
}

func buildSSDPQuery() []byte {
	query := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 3\r\n" +
		"ST: ssdp:all\r\n" +
		"\r\n"
	return []byte(query)
}

func isValidIP(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() != nil
}
