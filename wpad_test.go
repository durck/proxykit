package proxykit

import (
	"slices"
	"testing"
)

func TestDomainWalk(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"a.b.example.com", []string{"a.b.example.com", "b.example.com", "example.com"}},
		{"example.com", []string{"example.com"}},
		{"a.example.co.uk", []string{"a.example.co.uk", "example.co.uk"}},
		{"EXAMPLE.COM", []string{"example.com"}},
		{".example.com.", []string{"example.com"}},
		{"com", nil},   // bare TLD — never probe wpad.com
		{"co.uk", nil}, // public suffix
		{"corp", nil},  // single unmanaged label — documented limitation
		{"", nil},
	}
	for _, c := range cases {
		if got := domainWalk(c.in); !slices.Equal(got, c.want) {
			t.Errorf("domainWalk(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseResolvSearch(t *testing.T) {
	in := "# comment\nnameserver 1.1.1.1\nsearch corp.example.com sub.example.com\ndomain legacy.example.com extra.ignored\noptions ndots:2\n"
	got := parseResolvSearch(in)
	want := []string{"corp.example.com", "sub.example.com", "legacy.example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("parseResolvSearch = %v, want %v", got, want)
	}
}

func TestWpadDomains(t *testing.T) {
	cases := []struct {
		name     string
		hostname string
		search   []string
		want     []string
	}{
		{"fqdn walks to registrable domain", "host.corp.example.com", nil, []string{"corp.example.com", "example.com"}},
		{"plain host uses search domains", "host", []string{"corp.example.com"}, []string{"corp.example.com", "example.com"}},
		{"host and search de-duplicated", "host.example.com", []string{"example.com"}, []string{"example.com"}},
		{"no usable domain", "host", nil, nil},
		{"public-suffix host part ignored", "host.com", nil, nil},
	}
	for _, c := range cases {
		if got := wpadDomains(c.hostname, c.search); !slices.Equal(got, c.want) {
			t.Errorf("wpadDomains(%q, %v) = %v, want %v", c.hostname, c.search, got, c.want)
		}
	}
}
