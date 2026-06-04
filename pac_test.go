package proxykit

import (
	"slices"
	"testing"
)

func TestParsePACResult(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string // "DIRECT" or "scheme://host:port"
	}{
		{"empty", "", nil},
		{"direct only", "DIRECT", []string{"DIRECT"}},
		{"proxy", "PROXY p:8080", []string{"http://p:8080"}},
		{"proxy then direct", "PROXY p:8080; DIRECT", []string{"http://p:8080", "DIRECT"}},
		{"http alias", "HTTP p:8080", []string{"http://p:8080"}},
		{"https", "HTTPS p:8443", []string{"https://p:8443"}},
		{"socks", "SOCKS s:1080", []string{"socks5://s:1080"}},
		{"socks5", "SOCKS5 s:1080", []string{"socks5://s:1080"}},
		{"lowercase directives", "proxy p:8080; direct", []string{"http://p:8080", "DIRECT"}},
		{"multiple proxies then direct", "PROXY a:1; PROXY b:2; DIRECT", []string{"http://a:1", "http://b:2", "DIRECT"}},
		{"unknown token skipped", "FOO x:1; DIRECT", []string{"DIRECT"}},
		{"malformed proxy skipped", "PROXY; DIRECT", []string{"DIRECT"}},
		{"proxy default port", "PROXY p", []string{"http://p:80"}},
		{"socks default port", "SOCKS s", []string{"socks5://s:1080"}},
		{"stray whitespace and semicolons", " ; PROXY p:8080 ;; DIRECT ;", []string{"http://p:8080", "DIRECT"}},
		{"ipv6 proxy", "PROXY [::1]:8080", []string{"http://[::1]:8080"}},
		{"all unparseable", "FOO; BAR baz", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, r := range parsePACResult(tc.in) {
				if r.direct {
					got = append(got, "DIRECT")
				} else {
					got = append(got, r.url.String())
				}
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("parsePACResult(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
