package tests

import (
	"net"
	"testing"
)

func TestExpandHosts(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		want    int
		wantErr bool
	}{
		{"single host", "192.168.1.1/32", 1, false},
		{"point to point", "192.168.1.0/31", 2, false},
		{"small subnet", "192.168.1.0/30", 2, false},
		{"class C", "192.168.1.0/24", 254, false},
		{"invalid", "192.168.1.0/33", 0, true},
		{"invalid IP", "invalid/24", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := expandHosts(tt.cidr)
			if (err != nil) != tt.wantErr {
				t.Errorf("expandHosts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(got) != tt.want {
				t.Errorf("expandHosts() got %d hosts, want %d", len(got), tt.want)
			}
		})
	}
}

func TestIPConversions(t *testing.T) {
	tests := []struct {
		input string
	}{
		{"192.168.1.1"},
		{"10.0.0.1"},
		{"172.16.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ip := net.ParseIP(tt.input)
			if ip == nil {
				t.Fatalf("ParseIP returned nil for %s", tt.input)
			}

			num := ipToUint32(ip)
			result := uint32ToIP(num)

			if result.String() != tt.input {
				t.Errorf("round trip failed: %s -> %d -> %s", tt.input, num, result)
			}
		})
	}
}

func TestBitsSet(t *testing.T) {
	tests := []struct {
		input byte
		want  int
	}{
		{0b00000000, 0},
		{0b00000001, 1},
		{0b00000011, 2},
		{0b11111111, 8},
		{0b10101010, 4},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got := bitsSet(tt.input)
			if got != tt.want {
				t.Errorf("bitsSet(%b) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// Copy of internal functions for testing
func expandHosts(cidrStr string) ([]string, error) {
	_, network, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, err
	}

	mask := network.Mask
	networkIP := network.IP.To4()
	networkNum := ipToUint32(networkIP)
	broadcastNum := networkNum | (^ipToUint32(net.IP(mask)))

	var hosts []string

	prefix := 0
	for _, b := range mask {
		prefix += bitsSet(b)
	}

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
