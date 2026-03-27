package scan

import "strings"

// MACVendorLookup returns the vendor name for a given MAC address prefix
func MACVendorLookup(mac string) string {
	mac = normalizeMAC(mac)
	if len(mac) < 6 {
		return ""
	}

	prefix := mac[:8]
	if len(mac) == 12 {
		prefix = mac[:6]
		mac = prefix[:2] + ":" + prefix[2:4] + ":" + prefix[4:6]
		prefix = mac
	}

	vendors := map[string]string{
		// Apple
		"F4:6D:4D": "Apple", "F4:6D:3F": "Apple", "A4:83:E7": "Apple",
		"A4:5E:4C": "Apple", "00:26:08": "Apple", "00:1C:B3": "Apple",
		"00:21:E9": "Apple", "00:25:00": "Apple", "00:26:B0": "Apple",
		"00:26:BB": "Apple", "00:3E:E1": "Apple", "00:50:E4": "Apple",
		"00:56:CD": "Apple", "00:61:71": "Apple", "00:6D:52": "Apple",
		"00:C6:10": "Apple", "00:CD:FE": "Apple", "00:D7:95": "Apple",
		"00:DB:70": "Apple", "00:F4:B9": "Apple", "00:F7:6F": "Apple",
		"00:FC:8B": "Apple", "04:0C:CE": "Apple", "04:15:52": "Apple",
		"04:26:65": "Apple", "04:48:9A": "Apple", "04:52:F3": "Apple",
		"04:69:F8": "Apple", "04:D3:CF": "Apple", "04:DB:56": "Apple",
		"04:E5:36": "Apple", "04:F1:3E": "Apple", "04:F7:E4": "Apple",
		"08:00:07": "Apple", "08:66:98": "Apple", "08:74:02": "Apple",
		"0C:00:DE": "Apple", "0C:1D:AF": "Apple", "0C:77:1A": "Apple",
		"0C:8D:98": "Apple", "10:40:F3": "Apple", "14:10:9F": "Apple",
		"14:32:D1": "Apple", "14:40:2B": "Apple", "14:51:2E": "Apple",
		"14:98:D0": "Apple", "14:B4:BC": "Apple", "18:20:32": "Apple",
		"18:AF:8F": "Apple", "1C:1A:C0": "Apple", "20:C9:D0": "Apple",
		"24:AB:81": "Apple", "24:F0:94": "Apple", "28:6A:B8": "Apple",
		"28:CF:DA": "Apple", "2C:1F:23": "Apple", "2C:33:61": "Apple",
		"2C:F0:EE": "Apple", "30:10:E4": "Apple", "30:63:6B": "Apple",
		"30:7E:CB": "Apple", "30:C3:7D": "Apple", "34:51:C9": "Apple",
		"34:80:B3": "Apple", "38:0F:4A": "Apple", "38:C9:86": "Apple",
		"3C:07:54": "Apple", "3C:15:C2": "Apple", "40:0E:85": "Apple",
		"40:33:1A": "Apple", "40:A6:B7": "Apple", "44:D8:84": "Apple",
		"48:60:BC": "Apple", "4C:32:75": "Apple", "4C:57:CA": "Apple",
		"4C:B1:6C": "Apple", "50:32:37": "Apple", "50:E0:9B": "Apple",
		"54:26:96": "Apple", "54:72:4F": "Apple", "58:B0:35": "Apple",
		"5C:59:48": "Apple", "60:33:4B": "Apple", "60:C5:AD": "Apple",
		"64:20:0C": "Apple", "68:5B:35": "Apple", "68:A8:6D": "Apple",
		"6C:40:08": "Apple", "70:11:24": "Apple", "70:DE:E2": "Apple",
		"74:E1:B6": "Apple", "78:31:C1": "Apple", "78:7B:8A": "Apple",
		"7C:6D:62": "Apple", "80:92:9F": "Apple", "84:38:35": "Apple",
		"84:78:8B": "Apple", "88:66:5A": "Apple", "8C:00:6D": "Apple",
		"90:84:0D": "Apple", "90:B2:1F": "Apple", "94:E9:6A": "Apple",
		"98:01:A7": "Apple", "98:D2:93": "Apple", "98:FE:94": "Apple",
		"9C:04:EB": "Apple", "9C:20:7B": "Apple", "A8:5C:2C": "Apple",
		"AC:61:EA": "Apple", "B0:34:95": "Apple", "B4:99:BA": "Apple",
		"B8:17:C2": "Apple", "BC:52:B7": "Apple", "C4:2C:03": "Apple",
		"C8:69:CD": "Apple", "CC:08:E0": "Apple", "D4:F4:5F": "Apple",
		"DC:2B:2A": "Apple", "E0:5F:45": "Apple", "E4:C6:3D": "Apple",
		"E8:80:2E": "Apple", "F0:B4:29": "Apple", "F4:0B:93": "Apple",
		"F4:1B:A1": "Apple", "F4:6D:04": "Apple", "F8:1E:DF": "Apple",

		// Samsung
		"00:00:F0": "Samsung", "00:02:78": "Samsung", "00:07:AB": "Samsung",
		"00:09:18": "Samsung", "00:12:47": "Samsung", "00:12:FB": "Samsung",
		"00:13:77": "Samsung", "00:15:99": "Samsung", "00:16:32": "Samsung",
		"00:16:6B": "Samsung", "00:16:6C": "Samsung", "00:17:C9": "Samsung",
		"00:17:D5": "Samsung", "00:18:AF": "Samsung", "00:1A:8A": "Samsung",
		"00:1B:98": "Samsung", "00:1C:43": "Samsung", "00:1D:25": "Samsung",
		"00:1D:F6": "Samsung", "00:1E:7D": "Samsung", "00:1F:CC": "Samsung",
		"00:1F:CD": "Samsung", "00:21:19": "Samsung", "00:21:4C": "Samsung",
		"00:21:D1": "Samsung", "00:21:D2": "Samsung", "00:23:39": "Samsung",
		"00:23:3A": "Samsung", "00:23:D6": "Samsung", "00:23:D7": "Samsung",
		"00:24:54": "Samsung", "00:24:90": "Samsung", "00:24:91": "Samsung",
		"00:25:66": "Samsung", "00:25:67": "Samsung", "00:26:37": "Samsung",
		"00:26:5D": "Samsung", "00:26:5F": "Samsung",

		// LG
		"00:1F:E2": "LG", "00:1F:E3": "LG", "00:22:A1": "LG",
		"00:24:83": "LG", "00:25:E2": "LG", "00:E0:91": "LG",
		"08:27:A8": "LG", "10:F9:6F": "LG", "14:C9:13": "LG",
		"20:DF:B9": "LG", "28:21:0C": "LG", "28:94:E5": "LG",
		"34:FC:6F": "LG", "40:B0:76": "LG", "44:07:0B": "LG",
		"48:59:29": "LG", "4C:BC:A5": "LG", "54:92:BE": "LG",
		"5C:70:71": "LG", "64:99:5C": "LG", "6C:5C:B1": "LG",
		"70:8B:CD": "LG", "78:5D:C8": "LG", "7C:1C:4E": "LG",
		"88:C9:D0": "LG", "90:18:7C": "LG", "94:44:52": "LG",
		"9C:02:98": "LG", "A0:39:F7": "LG", "A4:08:42": "LG",
		"A8:16:B2": "LG", "B0:47:BF": "LG", "B4:39:D6": "LG",
		"B8:7A:9D": "LG", "BC:8C:CD": "LG", "C0:8A:3D": "LG",
		"C4:36:6C": "LG", "C8:02:10": "LG", "D0:13:FD": "LG",
		"D4:88:90": "LG", "D8:E0:E1": "LG", "E0:46:9A": "LG",
		"E0:AC:CB": "LG", "E4:12:1D": "LG", "E8:5B:5B": "LG",
		"F0:25:B7": "LG", "F4:E9:75": "LG",

		// Google/Chromecast
		"00:1A:11": "Google", "08:9E:08": "Google", "10:5F:CB": "Google",
		"18:D6:C7": "Google", "1C:F2:9A": "Google", "30:FD:38": "Google",
		"3C:5A:37": "Google", "40:B3:CC": "Google", "48:D6:D5": "Google",
		"54:60:09": "Google", "64:16:66": "Google", "7C:2E:BD": "Google",
		"94:EB:2C": "Google", "9C:88:C3": "Google", "A4:77:33": "Google",
		"F4:F5:D8": "Google", "F4:F5:E8": "Google",

		// Amazon
		"0C:47:C9": "Amazon", "10:AE:60": "Amazon", "14:EB:33": "Amazon",
		"18:74:2E": "Amazon", "34:D2:70": "Amazon", "38:F7:3D": "Amazon",
		"40:A2:DB": "Amazon", "44:65:0D": "Amazon", "48:8A:D2": "Amazon",
		"50:DC:E7": "Amazon", "50:F5:DA": "Amazon", "68:37:E9": "Amazon",
		"68:54:FD": "Amazon", "74:75:48": "Amazon", "74:C2:46": "Amazon",
		"78:E1:03": "Amazon", "84:D6:D0": "Amazon", "8C:C8:CD": "Amazon",
		"94:D9:B3": "Amazon", "AC:63:BE": "Amazon", "B4:7C:9C": "Amazon",
		"F0:27:2D": "Amazon", "F0:81:73": "Amazon",

		// Microsoft
		"00:03:FF": "Microsoft", "00:0D:3A": "Microsoft", "00:12:5A": "Microsoft",
		"00:15:5D": "Microsoft", "00:17:FA": "Microsoft", "00:1D:D8": "Microsoft",
		"00:22:48": "Microsoft", "00:25:AE": "Microsoft", "00:50:F2": "Microsoft",
		"28:18:78": "Microsoft", "30:59:B7": "Microsoft", "34:C9:3D": "Microsoft",
		"3C:83:75": "Microsoft", "50:1A:C5": "Microsoft", "58:82:A8": "Microsoft",
		"5C:E0:C5": "Microsoft", "60:45:BD": "Microsoft", "64:4B:F0": "Microsoft",
		"70:B5:E8": "Microsoft", "7C:1E:52": "Microsoft", "7C:ED:8D": "Microsoft",
		"84:EF:18": "Microsoft", "98:5F:D3": "Microsoft", "B4:0E:DE": "Microsoft",
		"B8:31:B5": "Microsoft", "BC:77:37": "Microsoft", "C8:3F:26": "Microsoft",
		"DC:B4:C4": "Microsoft",

		// Intel
		"00:02:B3": "Intel", "00:03:47": "Intel", "00:04:23": "Intel",
		"00:0E:0C": "Intel", "00:0E:35": "Intel", "00:11:11": "Intel",
		"00:12:F0": "Intel", "00:13:02": "Intel", "00:13:20": "Intel",
		"00:13:CE": "Intel", "00:13:E8": "Intel", "00:15:00": "Intel",
		"00:15:17": "Intel", "00:16:6F": "Intel", "00:16:76": "Intel",
		"00:16:EA": "Intel", "00:16:EB": "Intel", "00:18:DE": "Intel",
		"00:19:D1": "Intel", "00:19:D2": "Intel", "00:1B:21": "Intel",
		"00:1B:77": "Intel", "00:1C:BF": "Intel", "00:1C:C0": "Intel",
		"00:1D:E0": "Intel", "00:1D:E1": "Intel", "00:1E:64": "Intel",
		"00:1E:65": "Intel", "00:1E:67": "Intel", "00:1F:3B": "Intel",
		"00:1F:3C": "Intel", "00:20:E0": "Intel", "00:21:5C": "Intel",
		"00:21:5D": "Intel", "00:21:6A": "Intel", "00:21:6B": "Intel",
		"00:22:FA": "Intel", "00:22:FB": "Intel", "00:24:D6": "Intel",
		"00:24:D7": "Intel", "00:26:C6": "Intel", "00:26:C7": "Intel",
		"00:27:10": "Intel",

		// Dell
		"00:06:5B": "Dell", "00:08:74": "Dell", "00:0B:DB": "Dell",
		"00:0D:56": "Dell", "00:0F:1F": "Dell", "00:11:43": "Dell",
		"00:12:3F": "Dell", "00:13:72": "Dell", "00:14:22": "Dell",
		"00:15:C5": "Dell", "00:16:F0": "Dell", "00:18:8B": "Dell",
		"00:19:B9": "Dell", "00:1A:A0": "Dell", "00:1C:23": "Dell",
		"00:1D:09": "Dell", "00:1E:4F": "Dell", "00:1E:C9": "Dell",
		"00:21:70": "Dell", "00:21:9B": "Dell", "00:22:19": "Dell",
		"00:23:AE": "Dell", "00:24:E8": "Dell", "00:25:64": "Dell",
		"00:26:B9": "Dell",

		// HP
		"00:01:E6": "HP", "00:01:E7": "HP", "00:02:A5": "HP",
		"00:04:EA": "HP", "00:08:02": "HP", "00:08:83": "HP",
		"00:0A:57": "HP", "00:0B:CD": "HP", "00:0D:9D": "HP",
		"00:0E:7F": "HP", "00:0F:20": "HP", "00:0F:61": "HP",
		"00:10:83": "HP", "00:11:0A": "HP", "00:12:79": "HP",
		"00:13:21": "HP", "00:14:38": "HP", "00:14:C2": "HP",
		"00:16:35": "HP", "00:17:08": "HP", "00:17:A4": "HP",
		"00:18:71": "HP", "00:18:FE": "HP", "00:19:BB": "HP",
		"00:1A:4B": "HP", "00:1B:78": "HP", "00:1C:2E": "HP",
		"00:1C:C4": "HP", "00:1D:B3": "HP", "00:1E:0B": "HP",
		"00:1F:29": "HP", "00:21:5A": "HP", "00:22:64": "HP",
		"00:23:7D": "HP", "00:24:81": "HP",

		// TP-Link
		"00:1D:0F": "TP-Link", "00:27:19": "TP-Link", "14:CC:20": "TP-Link",
		"14:CF:92": "TP-Link", "18:A6:F7": "TP-Link", "1C:3B:F3": "TP-Link",
		"30:B5:C2": "TP-Link", "50:3E:AA": "TP-Link", "54:C8:0F": "TP-Link",
		"5C:E8:83": "TP-Link", "60:E3:27": "TP-Link", "64:66:B3": "TP-Link",
		"64:70:02": "TP-Link", "6C:5A:B3": "TP-Link", "78:A1:06": "TP-Link",
		"90:F6:52": "TP-Link", "98:DA:C4": "TP-Link", "A0:F3:C1": "TP-Link",
		"B0:4E:26": "TP-Link", "B0:95:75": "TP-Link", "C0:25:E9": "TP-Link",
		"C4:6E:1F": "TP-Link", "C8:3A:35": "TP-Link", "D4:6E:0E": "TP-Link",
		"D8:07:B6": "TP-Link", "E4:D3:32": "TP-Link", "E8:DE:27": "TP-Link",
		"EC:08:6B": "TP-Link", "F0:F3:36": "TP-Link", "F4:EC:38": "TP-Link",
		"F8:1A:67": "TP-Link",

		// Netgear
		"00:09:5B": "Netgear", "00:0F:B5": "Netgear", "00:14:6C": "Netgear",
		"00:18:4D": "Netgear", "00:1B:2F": "Netgear", "00:1E:2A": "Netgear",
		"00:1F:33": "Netgear", "00:22:3F": "Netgear", "00:24:B2": "Netgear",
		"00:26:F2": "Netgear", "08:BD:43": "Netgear", "10:0C:6B": "Netgear",
		"20:0C:C8": "Netgear", "28:C6:8E": "Netgear", "2C:B0:5D": "Netgear",
		"30:46:9A": "Netgear", "38:94:ED": "Netgear", "44:94:FC": "Netgear",
		"6C:B0:CE": "Netgear", "84:1B:5E": "Netgear", "9C:3D:CF": "Netgear",
		"A0:21:B7": "Netgear", "A4:2B:8C": "Netgear", "B0:7F:B9": "Netgear",
		"C0:3F:0E": "Netgear", "C4:04:15": "Netgear", "C8:9E:43": "Netgear",
		"CC:40:D0": "Netgear", "E0:91:F5": "Netgear", "E4:F4:C6": "Netgear",

		// Sony
		"00:00:C3": "Sony", "00:01:4A": "Sony", "00:04:1F": "Sony",
		"00:0A:D9": "Sony", "00:0B:A2": "Sony", "00:0E:07": "Sony",
		"00:0F:DE": "Sony", "00:12:EE": "Sony", "00:13:15": "Sony",
		"00:13:E9": "Sony", "00:15:C1": "Sony", "00:16:4A": "Sony",
		"00:16:FF": "Sony", "00:18:13": "Sony", "00:19:63": "Sony",
		"00:19:C5": "Sony", "00:1A:80": "Sony", "00:1D:0D": "Sony",
		"00:1D:BA": "Sony", "00:1F:A7": "Sony", "00:24:8D": "Sony",
		"00:24:DD": "Sony", "00:26:4D": "Sony", "28:0D:D8": "Sony",
		"30:1A:FD": "Sony", "38:6D:83": "Sony", "58:48:22": "Sony",
		"70:9E:29": "Sony", "78:84:3C": "Sony", "8C:5C:A2": "Sony",
		"90:FB:A6": "Sony", "98:E7:F4": "Sony", "A8:E3:EE": "Sony",
		"B8:3E:59": "Sony", "C0:91:34": "Sony", "C8:63:F1": "Sony",
		"D8:D4:3C": "Sony", "E8:CC:18": "Sony", "F8:CC:F6": "Sony",

		// Nintendo
		"00:09:BF": "Nintendo", "00:16:56": "Nintendo", "00:17:AB": "Nintendo",
		"00:19:1D": "Nintendo", "00:19:FD": "Nintendo", "00:1A:E9": "Nintendo",
		"00:1B:7A": "Nintendo", "00:1B:EA": "Nintendo", "00:1C:BE": "Nintendo",
		"00:1D:BC": "Nintendo", "00:1E:35": "Nintendo", "00:1F:32": "Nintendo",
		"00:1F:C5": "Nintendo", "00:21:47": "Nintendo", "00:21:BD": "Nintendo",
		"00:22:4C": "Nintendo", "00:22:AA": "Nintendo", "00:23:31": "Nintendo",
		"00:23:CC": "Nintendo", "00:24:1E": "Nintendo", "00:24:F3": "Nintendo",
		"00:26:59": "Nintendo", "00:27:09": "Nintendo",

		// Xiaomi
		"00:9E:C8": "Xiaomi", "28:6C:07": "Xiaomi", "3C:BD:D8": "Xiaomi",
		"4C:63:71": "Xiaomi", "58:44:98": "Xiaomi", "5C:92:5E": "Xiaomi",
		"64:09:80": "Xiaomi", "64:B4:73": "Xiaomi", "68:AB:1E": "Xiaomi",
		"74:23:44": "Xiaomi", "78:02:F8": "Xiaomi", "7C:1D:D9": "Xiaomi",
		"84:F3:EB": "Xiaomi", "8C:BF:A6": "Xiaomi", "9C:99:A0": "Xiaomi",
		"A4:77:F5": "Xiaomi", "B0:E2:35": "Xiaomi", "B8:86:0B": "Xiaomi",
		"C4:0B:CB": "Xiaomi", "D4:97:0B": "Xiaomi", "F8:A4:5F": "Xiaomi",

		// Huawei
		"00:1E:10": "Huawei", "00:25:68": "Huawei", "00:25:9E": "Huawei",
		"00:34:FE": "Huawei", "00:46:4B": "Huawei", "00:5A:13": "Huawei",
		"00:9A:CD": "Huawei", "00:E0:FC": "Huawei", "00:F8:1C": "Huawei",
		"04:02:1F": "Huawei", "04:25:C5": "Huawei", "04:4A:50": "Huawei",
		"04:75:03": "Huawei", "04:B0:E7": "Huawei", "04:C0:6F": "Huawei",
		"04:F9:38": "Huawei", "08:19:A6": "Huawei", "08:63:61": "Huawei",
		"0C:37:DC": "Huawei", "0C:96:BF": "Huawei", "10:1B:54": "Huawei",
		"10:47:80": "Huawei", "10:C6:1F": "Huawei", "14:B9:68": "Huawei",
		"14:FE:B5": "Huawei", "18:C5:8A": "Huawei", "1C:1D:67": "Huawei",
		"1C:8E:5C": "Huawei", "20:08:ED": "Huawei", "20:0B:C7": "Huawei",
		"20:A6:80": "Huawei", "24:09:95": "Huawei", "24:1F:A0": "Huawei",
		"24:69:68": "Huawei", "24:7F:3C": "Huawei", "24:DF:6A": "Huawei",
		"28:31:52": "Huawei", "28:6E:D4": "Huawei", "2C:AB:00": "Huawei",

		// Roku
		"00:0D:4B": "Roku", "08:05:81": "Roku", "10:59:32": "Roku",
		"20:EF:BD": "Roku", "2C:E4:09": "Roku", "3C:A7:3B": "Roku",
		"40:B3:95": "Roku", "58:FD:20": "Roku", "84:EA:ED": "Roku",
		"88:DE:A9": "Roku", "8C:49:62": "Roku", "90:1A:C3": "Roku",
		"AC:3A:7A": "Roku", "B0:A7:37": "Roku", "C8:3A:6B": "Roku",
		"CC:6D:A0": "Roku", "D8:31:34": "Roku", "DC:3A:5E": "Roku",

		// Sonos
		"00:0E:58": "Sonos", "00:15:6B": "Sonos", "00:1A:B3": "Sonos",
		"00:1E:58": "Sonos", "00:21:7D": "Sonos", "00:22:6B": "Sonos",
		"00:26:4A": "Sonos", "00:27:04": "Sonos", "00:28:D5": "Sonos",
		"00:E7:63": "Sonos", "04:4E:AF": "Sonos", "10:2D:B7": "Sonos",
		"14:3E:CF": "Sonos", "1C:28:AF": "Sonos", "20:1F:3B": "Sonos",
		"28:1F:3B": "Sonos", "2C:87:2C": "Sonos", "34:2D:0A": "Sonos",
		"38:2C:4A": "Sonos", "3C:1E:04": "Sonos", "48:2C:A0": "Sonos",
		"54:08:0A": "Sonos", "5C:87:2C": "Sonos", "74:C2:5A": "Sonos",
		"78:1F:DB": "Sonos", "80:87:98": "Sonos", "84:D6:05": "Sonos",
		"8C:71:D8": "Sonos", "90:1F:02": "Sonos", "A8:1B:38": "Sonos",
		"B8:E9:37": "Sonos", "C8:2E:0A": "Sonos", "D0:4D:2C": "Sonos",
	}

	if vendor, ok := vendors[prefix]; ok {
		return vendor
	}

	return ""
}

func normalizeMAC(mac string) string {
	mac = strings.ToUpper(mac)
	mac = strings.ReplaceAll(mac, "-", ":")
	mac = strings.ReplaceAll(mac, " ", "")
	return mac
}
