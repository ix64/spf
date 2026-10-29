package spf

import (
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		input string
		want  string // canonical form
	}{
		{"v=spf1", "v=spf1"},
		{"v=spf1 -all", "v=spf1 -all"},
		{"V=SpF1 +MX ~ALL", "v=spf1 mx ~all"},
		{"v=spf1  a  -all ", "v=spf1 a -all"},
		{"v=spf1 a:example.com/24//64 mx/30 ptr:example.org ?all", "v=spf1 a:example.com/24//64 mx/30 ptr:example.org ?all"},
		{"v=spf1 a:foo:bar/baz.example.com", "v=spf1 a:foo:bar/baz.example.com"},
		{"v=spf1 a//0 a/0 mx/32//128", "v=spf1 a//0 a/0 mx"},
		{"v=spf1 ip4:192.0.2.1/24 ip6:2001:DB8::/32 ip4:192.0.2.1 ip6:::ffff:1.2.3.4", "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 ip4:192.0.2.1 ip6:::ffff:1.2.3.4"},
		{"v=spf1 include:_spf.%{d2} exists:%{ir}.%{l1r+}.%{d} -all", "v=spf1 include:_spf.%{d2} exists:%{ir}.%{l1r+}.%{d} -all"},
		{"v=spf1 moo.cow-far_out=man:dog/cat default=pass -all", "v=spf1 -all"},
		{"v=spf1 Redirect=_spf.example.com exp=explain.%{d}", "v=spf1 redirect=_spf.example.com exp=explain.%{d}"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			rec, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if got := rec.String(); got != tt.want {
				t.Errorf("Parse().String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParse_invalid(t *testing.T) {
	for _, input := range []string{
		"", "spf2.0/pra", "v=spf10", "v=spf1\t-all",

		// syntax errors anywhere in the record
		"v=spf1 ip4:1.2.3.4 -all moo",
		"v=spf1 a:ctrl.example.com\rptr -all",
		"v=spf1 -",
		"v=spf1 all:example.com",
		"v=spf1 include",
		"v=spf1 include:",
		"v=spf1 exists:mail.example.com/24",
		"v=spf1 a:example",
		"v=spf1 a/33",
		"v=spf1 a//129",
		"v=spf1 a/024",
		"v=spf1 ip6",
		"v=spf1 ip4:2001:db8::1",
		"v=spf1 ip6:192.0.2.1",
		"v=spf1 ip4:192.0.2.1/33",
		"v=spf1 ip4:192.0.2.1/024",
		"v=spf1 ip4:192.0.2.1/",
		"v=spf1 ip6:fe80::1%eth0",

		// modifiers
		"v=spf1 redirect:example.com",
		"v=spf1 redirect=",
		"v=spf1 redirect=-all",
		"v=spf1 redirect=a.example.com redirect=b.example.com",
		"v=spf1 exp=",
		"v=spf1 exp=-all",
		"v=spf1 exp=a.example.com exp=b.example.com",
		"v=spf1 exp=%{r}.example.com",
		"v=spf1 foo=%abc",
	} {
		t.Run(input, func(t *testing.T) {
			if rec, err := Parse(input); err == nil {
				t.Errorf("Parse(%q) = %q, expected error", input, rec)
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"v=spf1 -all",
		"v=spf1 a:example.com/24//64 mx/30 ptr:example.org ?all",
		"v=spf1 ip4:192.0.2.1/24 ip6:2001:db8::/32",
		"v=spf1 include:_spf.%{d2} exists:%{ir}.%{l1r+}.%{d} -all",
		"v=spf1 moo.cow-far_out=man:dog/cat redirect=_spf.example.com exp=explain.%{d}",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		rec, err := Parse(input)
		if err != nil {
			return
		}
		// the canonical form must parse to itself
		canonical := rec.String()
		rec2, err := Parse(canonical)
		if err != nil {
			t.Fatalf("Parse(%q) error = %v, canonical form of %q", canonical, err, input)
		}
		if got := rec2.String(); got != canonical {
			t.Fatalf("Parse(%q).String() = %q, canonical form of %q", canonical, got, input)
		}
	})
}
