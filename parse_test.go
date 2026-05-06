package proxykit

import (
	"strings"
	"testing"
)

func TestParseProxyURL_Valid(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		wantScheme string
		wantHost   string
		wantUser   string // username[:password], empty if no userinfo
	}{
		{"http with port", "http://proxy:8080", "http", "proxy:8080", ""},
		{"http default port", "http://proxy", "http", "proxy:80", ""},
		{"https with port", "https://proxy:8443", "https", "proxy:8443", ""},
		{"https default port", "https://proxy.example.com", "https", "proxy.example.com:443", ""},
		{"socks5 with port", "socks5://proxy:1080", "socks5", "proxy:1080", ""},
		{"socks5 default port", "socks5://proxy", "socks5", "proxy:1080", ""},
		{"socks alias", "socks://proxy", "socks", "proxy:1080", ""},
		{"bare host:port", "proxy:8080", "http", "proxy:8080", ""},
		{"bare hostname", "proxy.example.com", "http", "proxy.example.com:80", ""},
		{"bare ipv4:port", "1.2.3.4:8080", "http", "1.2.3.4:8080", ""},
		{"with userinfo", "http://user:pass@proxy:8080", "http", "proxy:8080", "user:pass"},
		{"with username only", "http://user@proxy:8080", "http", "proxy:8080", "user"},
		{"ipv4", "http://1.2.3.4:8080", "http", "1.2.3.4:8080", ""},
		{"ipv6 with port", "http://[::1]:8080", "http", "[::1]:8080", ""},
		{"ipv6 default port", "http://[::1]", "http", "[::1]:80", ""},
		{"uppercase scheme", "HTTP://proxy:8080", "http", "proxy:8080", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := ParseProxyURL(tt.in)
			if err != nil {
				t.Fatalf("ParseProxyURL(%q) returned error: %v", tt.in, err)
			}
			if u.Scheme != tt.wantScheme {
				t.Errorf("scheme = %q, want %q", u.Scheme, tt.wantScheme)
			}
			if u.Host != tt.wantHost {
				t.Errorf("host = %q, want %q", u.Host, tt.wantHost)
			}
			gotUser := ""
			if u.User != nil {
				gotUser = u.User.String()
			}
			if gotUser != tt.wantUser {
				t.Errorf("user = %q, want %q", gotUser, tt.wantUser)
			}
		})
	}
}

func TestParseProxyURL_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		wantSubstr string
	}{
		{"empty", "", "empty proxy URL"},
		{"socks4 rejected", "socks4://proxy:1080", "unsupported proxy scheme"},
		{"socks4a rejected", "socks4a://proxy:1080", "unsupported proxy scheme"},
		{"ftp rejected", "ftp://proxy", "unsupported proxy scheme"},
		{"gopher rejected", "gopher://x", "unsupported proxy scheme"},
		{"scheme only", "http://", "no host"},
		{"control char", "http://proxy\x00", "invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseProxyURL(tt.in)
			if err == nil {
				t.Fatalf("ParseProxyURL(%q) returned nil error, want error containing %q", tt.in, tt.wantSubstr)
			}
			if !strings.Contains(err.Error(), tt.wantSubstr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantSubstr)
			}
		})
	}
}
