package scan

import (
	"fmt"
	"net"
	"time"
)

var httpTimeout = 2 * time.Second

type HTTPInfo struct {
	Server   string
	Title    string
	Response string
}

func probeHTTP(ip string) HTTPInfo {
	info := HTTPInfo{}

	ports := []int{80, 443, 8080, 8443}

	for _, port := range ports {
		info = fetchHTTP(ip, port)
		if info.Server != "" || info.Title != "" {
			break
		}
	}

	return info
}

func fetchHTTP(ip string, port int) HTTPInfo {
	info := HTTPInfo{}
	addr := fmt.Sprintf("%s:%d", ip, port)

	conn, err := net.DialTimeout("tcp", addr, httpTimeout)
	if err != nil {
		return info
	}
	defer conn.Close()

	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", ip)
	_, err = conn.Write([]byte(req))
	if err != nil {
		return info
	}

	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return info
	}

	response := string(buffer[:n])
	info.Response = response

	lines := splitLines(response)
	for _, line := range lines {
		line = trimSpace(line)
		if hasPrefixCI(line, "Server:") {
			info.Server = trimPrefix(line, "Server:")
			info.Server = trimSpace(info.Server)
		}
	}

	info.Title = extractTitle(response)

	return info
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func hasPrefixCI(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return toLower(s[:len(prefix)]) == toLower(prefix)
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r' || s[start] == '\n') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\r' || s[end-1] == '\n') {
		end--
	}
	return s[start:end]
}

func trimPrefix(s, prefix string) string {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}

func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c = c + 32
		}
		result[i] = c
	}
	return string(result)
}

func extractTitle(response string) string {
	lower := toLower(response)
	idx := find(lower, "<title>")
	if idx == -1 {
		idx = find(lower, "<title ")
	}
	if idx == -1 {
		return ""
	}

	start := idx + 7
	endIdx := find(lower[start:], "</title>")
	if endIdx == -1 {
		return ""
	}

	end := start + endIdx
	title := response[start:end]
	title = trimSpace(title)

	title = replaceAll(title, "\n", " ")
	title = replaceAll(title, "\r", " ")
	title = replaceAll(title, "\t", " ")

	return title
}

func find(s, substr string) int {
	if len(substr) == 0 {
		return 0
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func replaceAll(s, old, new string) string {
	result := ""
	for {
		idx := find(s, old)
		if idx == -1 {
			result += s
			break
		}
		result += s[:idx] + new
		s = s[idx+len(old):]
	}
	return result
}
