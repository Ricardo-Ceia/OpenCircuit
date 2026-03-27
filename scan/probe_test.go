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
}
