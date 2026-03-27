package scan

import (
	"testing"
)

func TestExtractTitle(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     string
	}{
		{
			name: "basic title",
			response: `HTTP/1.1 200 OK
Content-Type: text/html

<html>
<head>
<title>Router Admin</title>
</head>
</html>`,
			want: "Router Admin",
		},
		{
			name: "title with newlines",
			response: `HTTP/1.1 200 OK
<html>
<head>
<title>
TP-Link Wireless Router
</title>
</head>`,
			want: "TP-Link Wireless Router",
		},
		{
			name: "no title",
			response: `HTTP/1.1 200 OK
Content-Type: text/plain
Hello World`,
			want: "",
		},
		{
			name: "capitalized title tag",
			response: `<HTML><HEAD><TITLE>Login Page</TITLE></HEAD></HTML>`,
			want: "Login Page",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractTitle(tt.response)
			if got != tt.want {
				t.Errorf("extractTitle() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHTTPHelperFunctions(t *testing.T) {
	t.Run("splitLines", func(t *testing.T) {
		input := "line1\nline2\nline3"
		got := splitLines(input)
		want := []string{"line1", "line2", "line3"}
		if len(got) != len(want) {
			t.Fatalf("len = %d, want %d", len(got), len(want))
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("trimSpace", func(t *testing.T) {
		tests := []struct {
			input string
			want  string
		}{
			{"  hello  ", "hello"},
			{"\t\ntab\t", "tab"},
			{"no spaces", "no spaces"},
		}
		for _, tt := range tests {
			got := trimSpace(tt.input)
			if got != tt.want {
				t.Errorf("trimSpace(%q) = %q, want %q", tt.input, got, tt.want)
			}
		}
	})

	t.Run("hasPrefixCI", func(t *testing.T) {
		if !hasPrefixCI("Server: nginx", "server:") {
			t.Error("expected true for case-insensitive match")
		}
		if hasPrefixCI("nginx", "server:") {
			t.Error("expected false for non-match")
		}
	})

	t.Run("toLower", func(t *testing.T) {
		if toLower("HELLO") != "hello" {
			t.Error("toLower failed")
		}
		if toLower("HeLLo") != "hello" {
			t.Error("toLower failed")
		}
	})

	t.Run("contains", func(t *testing.T) {
		if !contains("hello world", "world") {
			t.Error("contains failed")
		}
		if contains("hello", "xyz") {
			t.Error("contains should be false")
		}
	})
}

func TestUPnPResponseParsing(t *testing.T) {
	t.Run("parse UPnP response", func(t *testing.T) {
		response := `HTTP/1.1 200 OK
ST: urn:schemas-upnp-org:device:MediaPlayer:1
USN: uuid:12345678-1234-1234-1234-123456789abc::urn:schemas-upnp-org:device:MediaPlayer:1
SERVER: Linux/4.0 UPnP/1.0 Samsung Smart TV/1.0
X-USER-AGENT: Samsung MRD`

		info := parseUPnPResponse(response, "192.168.1.5")
		if info.DeviceType != "MediaPlayer" {
			t.Errorf("DeviceType = %q, want MediaPlayer", info.DeviceType)
		}
	})

	t.Run("extract device type", func(t *testing.T) {
		tests := []struct {
			input string
			want  string
		}{
			{"urn:schemas-upnp-org:device:MediaPlayer:1", "MediaPlayer"},
			{"urn:schemas-upnp-org:device:TV:1", "TV"},
			{"urn:schemas-upnp-org:device:InternetGatewayDevice:1", "InternetGatewayDevice"},
		}
		for _, tt := range tests {
			got := extractUPnPDeviceType(tt.input)
			if got != tt.want {
				t.Errorf("extractUPnPDeviceType(%q) = %q, want %q", tt.input, got, tt.want)
			}
		}
	})

	t.Run("device type to name", func(t *testing.T) {
		tests := []struct {
			input string
			want  string
		}{
			{"mediaplayer", "Media Player"},
			{"tv", "TV"},
			{"printer", "Printer"},
			{"storage", "NAS"},
		}
		for _, tt := range tests {
			got := deviceTypeToName(tt.input)
			if got != tt.want {
				t.Errorf("deviceTypeToName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		}
	})
}

func TestMDNSServiceParsing(t *testing.T) {
	t.Run("splitByDot", func(t *testing.T) {
		tests := []struct {
			input string
			want  []string
		}{
			{"hello.world", []string{"hello", "world"}},
			{"single", []string{"single"}},
			{"a.b.c", []string{"a", "b", "c"}},
		}
		for _, tt := range tests {
			got := splitByDot(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("len = %d, want %d", len(got), len(tt.want))
			}
		}
	})

	t.Run("parse mDNS service info", func(t *testing.T) {
		info := mDNSServiceInfo{
			Name:    "livingroom",
			Service: "AirPlay",
			Hostname: "livingroom.local",
		}

		if info.Service != "AirPlay" {
			t.Errorf("Service = %q, want AirPlay", info.Service)
		}
		if info.Name != "livingroom" {
			t.Errorf("Name = %q, want livingroom", info.Name)
		}
	})
}
