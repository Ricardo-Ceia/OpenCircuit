package scan

import "testing"

func TestMACVendorLookup(t *testing.T) {
	tests := []struct {
		name   string
		mac    string
		want   string
	}{
		{"Apple MAC", "F4:6D:4D:12:34:56", "Apple"},
		{"Samsung MAC", "00:12:47:AB:CD:EF", "Samsung"},
		{"Google MAC", "00:1A:11:12:34:56", "Google"},
		{"Amazon MAC", "0C:47:C9:12:34:56", "Amazon"},
		{"Microsoft MAC", "00:15:5D:12:34:56", "Microsoft"},
		{"Intel MAC", "00:1B:77:12:34:56", "Intel"},
		{"Dell MAC", "00:0D:56:12:34:56", "Dell"},
		{"TP-Link MAC", "14:CC:20:12:34:56", "TP-Link"},
		{"Netgear MAC", "00:0F:B5:12:34:56", "Netgear"},
		{"Xiaomi MAC", "28:6C:07:12:34:56", "Xiaomi"},
		{"Huawei MAC", "00:1E:10:12:34:56", "Huawei"},
		{"Roku MAC", "00:0D:4B:12:34:56", "Roku"},
		{"Sonos MAC", "00:0E:58:12:34:56", "Sonos"},
		{"Nintendo MAC", "00:09:BF:12:34:56", "Nintendo"},
		{"Sony MAC", "00:01:4A:12:34:56", "Sony"},
		{"LG MAC", "00:1F:E2:12:34:56", "LG"},
		{"lowercase MAC", "f4:6d:4d:12:34:56", "Apple"},
		{"dash separator", "F4-6D-4D-12-34-56", "Apple"},
		{"no separator", "F46D4D123456", "Apple"},
		{"unknown MAC", "AA:BB:CC:12:34:56", ""},
		{"too short", "F4:6D", ""},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MACVendorLookup(tt.mac)
			if got != tt.want {
				t.Errorf("MACVendorLookup(%q) = %q, want %q", tt.mac, got, tt.want)
			}
		})
	}
}

func TestInferDeviceType(t *testing.T) {
	tests := []struct {
		name  string
		ports []int
		want  string
	}{
		{"RTSP stream", []int{554}, "tv"},
		{"Chromecast ports", []int{8008, 8009}, "tv"},
		{"Roku port", []int{9000}, "tv"},
		{"SSH", []int{22}, "computer"},
		{"iOS device", []int{62078}, "phone"},
		{"mDNS only", []int{5353}, "iot"},
		{"SSDP only", []int{1900}, "iot"},
		{"DNS + HTTP", []int{53, 80}, "router"},
		{"Printer", []int{631}, "printer"},
		{"No ports", []int{}, "unknown"},
		{"Unknown ports", []int{9999, 8888}, "unknown"},
		{"Multiple ports TV", []int{80, 554, 443}, "tv"},
		{"Computer with many ports", []int{22, 80, 443, 3389}, "computer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferDeviceType(tt.ports)
			if got != tt.want {
				t.Errorf("inferDeviceType(%v) = %q, want %q", tt.ports, got, tt.want)
			}
		})
	}
}

func TestDeviceDisplayName(t *testing.T) {
	tests := []struct {
		name string
		device Device
		want  string
	}{
		{"hostname takes priority", Device{Hostname: "my-laptop.local", Vendor: "Apple", DeviceType: "computer", IP: "192.168.1.5"}, "my-laptop.local"},
		{"vendor + type fallback", Device{Vendor: "Apple", DeviceType: "phone", IP: "192.168.1.10"}, "Apple phone"},
		{"vendor only fallback", Device{Vendor: "Samsung", IP: "192.168.1.20"}, "Samsung"},
		{"IP only fallback", Device{IP: "192.168.1.30"}, "192.168.1.30"},
		{"type without vendor", Device{DeviceType: "tv", IP: "192.168.1.40"}, "192.168.1.40"},
		{"unknown type ignored", Device{Vendor: "Apple", DeviceType: "unknown", IP: "192.168.1.50"}, "Apple"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.device.DisplayName()
			if got != tt.want {
				t.Errorf("DisplayName() = %q, want %q", got, tt.want)
			}
		})
	}
}
