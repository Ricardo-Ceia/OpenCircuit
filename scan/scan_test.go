package scan

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
