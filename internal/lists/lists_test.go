package lists

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseHosts(t *testing.T) {
	in := `
# StevenBlack hosts (snippet)
127.0.0.1   localhost
127.0.0.1   broadcasthost
0.0.0.0     doubleclick.net
0.0.0.0     ads.example.com   # inline comment
0.0.0.0     googleadservices.com
   0.0.0.0  Pagead2.googlesyndication.com
0.0.0.0     not_a_domain
0.0.0.0     -bad-leading-hyphen.com
`
	got, err := ParseHosts(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ads.example.com",
		"doubleclick.net",
		"googleadservices.com",
		"pagead2.googlesyndication.com",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v\nwant %#v", got, want)
	}
}

func TestParseAdblock(t *testing.T) {
	in := `
[Adblock Plus 2.0]
! Title: EasyPrivacy snippet
! Last modified: just now
||tracker.example.com^
||cdn.ads.example.org^$third-party
@@||allowed.example.com^
##.banner-ad
||UPPER.case.com^
||not_a_domain^
not-a-rule
`
	got, err := ParseAdblock(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"cdn.ads.example.org",
		"tracker.example.com",
		"upper.case.com",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v\nwant %#v", got, want)
	}
}

func TestParseDomain(t *testing.T) {
	in := `
# OISD-style snippet
ads.example.net
analytics.example.com  # inline comment
duplicate.example.org
duplicate.example.org
mixed.CASE.com
not_valid
`
	got, err := ParseDomain(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ads.example.net",
		"analytics.example.com",
		"duplicate.example.org",
		"mixed.case.com",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v\nwant %#v", got, want)
	}
}

func TestValidDomain(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"a-b.c-d.example.com", true},
		{"DOUBLE.click.NET", true}, // case-insensitive
		{"localhost", false},
		{"local", false},
		{"", false},
		{"no_underscore.com", false},
		{"-leading-hyphen.com", false},
		{"trailing-hyphen-.com", false},
		{"missing-tld", false},
		{strings.Repeat("a", 254) + ".com", false}, // too long
	}
	for _, c := range cases {
		if got := ValidDomain(c.in); got != c.want {
			t.Errorf("ValidDomain(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseDispatch(t *testing.T) {
	if _, err := Parse("nope", strings.NewReader("")); err == nil {
		t.Fatal("expected error for unknown format")
	}
	got, err := Parse(FormatDomain, strings.NewReader("ok.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "ok.example.com" {
		t.Fatalf("dispatch failed: %#v", got)
	}
}
