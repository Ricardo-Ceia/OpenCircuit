package scan

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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

	// Always add localhost if in range (common case)
	hostsMap := make(map[string]bool)
	for _, h := range hosts {
		hostsMap[h] = true
	}
	if hostsMap["127.0.0.1"] {
		deviceMap["127.0.0.1"] = Device{IP: "127.0.0.1", Status: "up"}
	}

	// Method 1: ARP Scan using gopacket (most reliable)
	// Falls back to UDP probes if pcap fails (no root)
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

	// Method 1b: UDP probe fallback (works without root)
	// Sends UDP packets to trigger ARP responses
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ip := range udpProbeScan(hosts) {
			mu.Lock()
			if existing, ok := deviceMap[ip]; ok {
				existing.Status = "up"
				deviceMap[ip] = existing
			} else {
				deviceMap[ip] = Device{IP: ip, Status: "recently_seen"}
			}
			mu.Unlock()
		}
	}()

	// Method 2: TCP probe (fallback for devices with open ports)
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

	// Method 3: mDNS scan (finds Apple devices, Chromecast, etc)
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

	// Method 4: SSDP scan (finds TVs, consoles, routers)
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

	// Try reverse DNS
	if len(device.Ports) > 0 {
		names, err := net.LookupAddr(ip)
		if err == nil && len(names) > 0 {
			device.Hostname = strings.TrimSuffix(names[0], ".")
		}
	}

	return device
}

// arpScan uses gopacket to send ARP requests to all hosts
// This is the most reliable method for local network discovery
func arpScan(hosts []string) chan string {
	results := make(chan string, 256)

	go func() {
		defer close(results)

		// Find network interface
		iface, err := findInterface()
		if err != nil {
			fmt.Printf("ARP scan failed: %v\n", err)
			return
		}

		// Get source IP and MAC
		srcIP := getInterfaceIP(iface)
		srcMAC := getInterfaceMAC(iface)
		if srcIP == nil || srcMAC == nil {
			fmt.Println("ARP scan failed: could not get interface info")
			return
		}

		// Open handle for sending and receiving
		handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
		if err != nil {
			// Silently fail - will use UDP/TCP fallback
			return
		}
		defer handle.Close()

		// Set filter for ARP responses
		handle.SetBPFFilter("arp")

		// Create ARP packet for each IP
		for _, targetIP := range hosts {
			sendARPRequest(handle, iface.Name, srcMAC, srcIP, net.ParseIP(targetIP))
			select {
			case results <- targetIP:
			default:
			}
			time.Sleep(10 * time.Millisecond)
		}

		// Wait for responses
		packetSource := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
		respChan := packetSource.Packets()

		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()

		for {
			select {
			case packet := <-respChan:
				if packet == nil {
					continue
				}
				arpLayer := packet.Layer(layers.LayerTypeARP)
				if arpLayer != nil {
					arp := arpLayer.(*layers.ARP)
					if arp.Operation == 2 { // ARP Reply
						ip := net.IP(arp.SourceProtAddress).String()
						select {
						case results <- ip:
						default:
						}
					}
				}
			case <-timer.C:
				return
			}
		}
	}()

	return results
}

func findInterface() (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			return &iface, nil
		}
	}
	return nil, fmt.Errorf("no suitable network interface found")
}

func getInterfaceIP(iface *net.Interface) net.IP {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	for _, addr := range addrs {
		if ip, _, err := net.ParseCIDR(addr.String()); err == nil {
			if ip.To4() != nil {
				return ip
			}
		}
	}
	return nil
}

func getInterfaceMAC(iface *net.Interface) net.HardwareAddr {
	return iface.HardwareAddr
}

func sendARPRequest(handle *pcap.Handle, ifaceName string, srcMAC net.HardwareAddr, srcIP, targetIP net.IP) {
	// Convert MAC to byte array
	mac := [6]byte{}
	copy(mac[:], srcMAC[:6])

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         1, // ARP Request
		SourceHwAddress:   mac[:],
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    targetIP.To4(),
	}

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		FixLengths: true,
	}, &arp)

	handle.WritePacketData(buf.Bytes())
}

// udpProbeScan sends UDP packets to trigger ARP responses
// This works without root privileges
func udpProbeScan(hosts []string) chan string {
	results := make(chan string, 256)

	go func() {
		defer close(results)

		// Common ports that might trigger responses
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

		// Check ARP table for new entries
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
			if len(fields) >= 2 {
				ip := fields[0]
				if hostsMap[ip] && net.ParseIP(ip) != nil {
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

// mDNSScan discovers devices using mDNS (Multicast DNS)
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

		query := []byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}

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

// ssdpScan discovers devices using SSDP
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

		query := []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n")

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

func isValidIP(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() != nil
}
