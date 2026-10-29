package spf

import (
	"net/netip"
	"strings"
	"testing"
)

func Test_formatIPDotNotation(t *testing.T) {
	tests := []struct {
		name  string
		input netip.Addr
		want  string
	}{
		{"IPv4", netip.MustParseAddr("192.0.2.1"), "192.0.2.1"},
		{
			"IPv6",
			netip.MustParseAddr("2001:db8::1"),
			"2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatIPDotNotation(tt.input); got != tt.want {
				t.Errorf("formatIPDotNotation() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMacroString_expand(t *testing.T) {
	v4 := NewVerifier(
		"strong-bad@email.example.com",
		netip.MustParseAddr("192.0.2.3"),
		"another.example.com",
	).env("email.example.com")
	v6 := NewVerifier(
		"strong-bad@email.example.com",
		netip.MustParseAddr("2001:db8::cb01"),
		"another.example.com",
	).env("email.example.com")

	tests := []struct {
		env   *macroEnv
		input string
		want  string
	}{
		// https://datatracker.ietf.org/doc/html/rfc7208#section-7.4
		{v4, "%{s}", "strong-bad@email.example.com"},
		{v4, "%{o}", "email.example.com"},
		{v4, "%{d}", "email.example.com"},
		{v4, "%{d4}", "email.example.com"},
		{v4, "%{d3}", "email.example.com"},
		{v4, "%{d2}", "example.com"},
		{v4, "%{d1}", "com"},
		{v4, "%{dr}", "com.example.email"},
		{v4, "%{d2r}", "example.email"},
		{v4, "%{l}", "strong-bad"},
		{v4, "%{l-}", "strong.bad"},
		{v4, "%{lr}", "strong-bad"},
		{v4, "%{lr-}", "bad.strong"},
		{v4, "%{l1r-}", "strong"},

		{v4, "%{ir}.%{v}._spf.%{d2}", "3.2.0.192.in-addr._spf.example.com"},
		{v4, "%{lr-}.lp._spf.%{d2}", "bad.strong.lp._spf.example.com"},
		{v4, "%{lr-}.lp.%{ir}.%{v}._spf.%{d2}", "bad.strong.lp.3.2.0.192.in-addr._spf.example.com"},
		{v4, "%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}", "3.2.0.192.in-addr.strong.lp._spf.example.com"},
		{v4, "%{d2}.trusted-domains.example.net", "example.com.trusted-domains.example.net"},
		{
			v6,
			"%{ir}.%{v}._spf.%{d2}",
			"1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com",
		},
		{v4, "%{ir}.%{l1r+-}._spf.%{d}", "3.2.0.192.strong._spf.email.example.com"},

		// upper-case macro-letters are URL-escaped
		{v4, "%{S}", "strong-bad%40email.example.com"},
		{v4, "%{D2}", "example.com"},
		{v4, "macro%%percent%_space%-url-space", "macro%percent space%20url-space"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			m, err := parseMacroString(tt.input)
			if err != nil {
				t.Fatalf("parseMacroString() error = %v", err)
			}
			got, err := m.expand(tt.env)
			if err != nil {
				t.Fatalf("expand() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("expand() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseMacroString_invalid(t *testing.T) {
	for _, input := range []string{
		"%", "%x", "%{", "%{}", "%{x}", "%{d0}", "%{d2q}",
		"%{c}", "%{r}", "%{t}", // only allowed in explanation strings
		"a b", "a\rb", "caf\xc3\xa9",
	} {
		t.Run(input, func(t *testing.T) {
			if _, err := parseMacroString(input); err == nil {
				t.Errorf("parseMacroString(%q) expected error", input)
			}
		})
	}
}

func Test_parseDomainSpec(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"example.com", false},
		{"example.com.", false},
		{"%{d}", false},
		{"%{d}.com", false},
		{"_spf.%{d2}", false},
		{"foo:bar/baz.example.com", false},
		{"1-2.example.123-4", false},

		{"", true},
		{"example", true},
		{"-all", true},
		{"%{d}com", true},
		{"mail.example.com/24", true},
		{"example.123", true},
		{"example.-com", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_, err := parseDomainSpec(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDomainSpec(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestMacroString_expandDomain_truncate(t *testing.T) {
	env := NewVerifier(
		"user@"+strings.Repeat("a", 60)+".example.com",
		netip.MustParseAddr("192.0.2.3"),
		"example.net",
	).env("example.com")

	m, err := parseDomainSpec("%{o}.%{o}.%{o}.%{o}.%{o}.example.com")
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.expandDomain(env)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) > 253 {
		t.Errorf("expandDomain() length = %d, want <= 253", len(got))
	}
	if !strings.HasSuffix(got, ".example.com.example.com") || strings.HasPrefix(got, ".") {
		t.Errorf("expandDomain() = %q, want left-side labels removed", got)
	}
}
