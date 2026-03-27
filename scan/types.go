package scan

import "strings"

type Device struct {
	IP           string
	Status       string
	Hostname     string
	FriendlyName string
	MAC          string
	Vendor       string
	DeviceType   string
	Ports        []int
	Services     []string
	HTTPInfo     string
	UPnPInfo     string
}

func (d *Device) DisplayName() string {
	if d.FriendlyName != "" {
		return d.FriendlyName
	}
	if d.Hostname != "" {
		return d.Hostname
	}
	if d.Vendor != "" && d.DeviceType != "" && d.DeviceType != "unknown" {
		return d.Vendor + " " + d.DeviceType
	}
	if d.Vendor != "" {
		return d.Vendor
	}
	return d.IP
}

func inferDeviceType(ports []int) string {
	portSet := make(map[int]bool)
	for _, p := range ports {
		portSet[p] = true
	}

	switch {
	case portSet[554] || portSet[8008] || portSet[8009] || portSet[9000]:
		return "tv"
	case portSet[62078]:
		return "phone"
	case portSet[5353] || portSet[1900]:
		return "iot"
	case portSet[631]:
		return "printer"
	case portSet[22]:
		return "computer"
	case portSet[53] && portSet[80]:
		return "router"
	case portSet[139] && portSet[445]:
		return "computer"
	default:
		return "unknown"
	}
}

func ExtractDeviceType(ports []int) string {
	return inferDeviceType(ports)
}

func ParseFriendlyName(parts ...string) string {
	var valid []string
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			valid = append(valid, strings.TrimSpace(p))
		}
	}
	return strings.Join(valid, " ")
}

func buildFriendlyName(d Device) string {
	if d.FriendlyName != "" {
		return d.FriendlyName
	}

	if d.UPnPInfo != "" {
		return d.UPnPInfo
	}

	if d.HTTPInfo != "" {
		return d.HTTPInfo
	}

	if d.Hostname != "" && !strings.HasSuffix(d.Hostname, ".local") {
		return d.Hostname
	}

	if d.Services != nil && len(d.Services) > 0 {
		serviceName := d.Services[0]
		if d.Vendor != "" {
			return d.Vendor + " " + serviceName
		}
		return serviceName
	}

	if d.Vendor != "" {
		return d.Vendor
	}

	return d.IP
}
