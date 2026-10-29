package spf

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/foxcpp/go-mockdns"
)

func TestVerifier_checkMechanismMX(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"example.com.": {
			MX: []net.MX{{Host: "mx.example.com", Pref: 5}},
		},
		"mail.example.com.": {
			MX: []net.MX{{Host: "mx.example.com", Pref: 5}},
		},

		"mx.example.com.": {
			A:    []string{"10.10.10.10"},
			AAAA: []string{"2001:db8::1"},
		},
	}}
	cases := []struct {
		stmt        string
		sender      string
		ip          string
		helloDomain string
		want        bool
		wantErr     bool
	}{
		{"mx", "test@example.com", "10.10.10.10", "example.net", true, false},
		{"mx/24", "test@example.com", "10.10.10.254", "example.net", true, false},
		{"mx:mail.example.com", "test@example.com", "10.10.10.10", "example.net", true, false},
		{"mx:mail.example.com/24", "test@example.com", "10.10.10.254", "example.net", true, false},

		{"mx", "test@example.com", "2001:db8::1", "example.net", true, false},
		{"mx//64", "test@example.com", "2001:0db8::ffff:0:0:1", "example.net", true, false},
		{"mx:mail.example.com//64", "test@example.com", "2001:0db8::ffff:0:0:1", "example.net", true, false},
		{"mx:mail.example.com/24//64", "test@example.com", "10.10.10.254", "example.net", true, false},
		{"mx:mail.example.com/24//64", "test@example.com", "2001:0db8::ffff:0:0:1", "example.net", true, false},

		{"mx", "test@example.com", "192.168.1.1", "example.net", false, false},
		// a domain without MX records does not match
		{"mx:non-exist.example.com", "test@example.com", "10.10.10.10", "example.net", false, false},
	}
	for _, tt := range cases {
		t.Run(tt.stmt, func(t *testing.T) {
			s := NewVerifier(tt.sender, netip.MustParseAddr(tt.ip), tt.helloDomain)
			s.SetResolver(resolver)
			rec, err := Parse("v=spf1 " + tt.stmt)
			if err != nil {
				t.Fatal(err)
			}
			e := &evaluation{Verifier: s, ctx: context.TODO()}
			matched, err := e.match(rec.Directives[0].Mechanism, s.env(s.senderDomain))
			if (err != nil) != tt.wantErr {
				t.Errorf("match() err = %v, want = %v", err, tt.wantErr)
			}
			if matched != tt.want {
				t.Errorf("match() matched = %v, want = %v", matched, tt.want)
			}
		})
	}

}

func Test_splitSender(t *testing.T) {
	tests := []struct {
		sender     string
		wantLocal  string
		wantDomain string
	}{
		{"strong-bad@email.example.com", "strong-bad", "email.example.com"},
		{"a@b@example.com", "a@b", "example.com"},
		{"@example.com", "postmaster", "example.com"},
		{"example.com", "postmaster", "example.com"},
		{"", "postmaster", "helo.example.net"},
	}
	for _, tt := range tests {
		t.Run(tt.sender, func(t *testing.T) {
			local, domain := splitSender(tt.sender, "helo.example.net")
			if local != tt.wantLocal || domain != tt.wantDomain {
				t.Errorf("splitSender(%q) = (%q, %q), want (%q, %q)",
					tt.sender, local, domain, tt.wantLocal, tt.wantDomain)
			}
		})
	}
}

// sender without local-part must not panic when %{l} is expanded
func TestVerifier_senderWithoutLocalPart(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"example.com.": {
			TXT: []string{"v=spf1 exists:%{l}.%{d} -all"},
		},
		"postmaster.example.com.": {
			A: []string{"127.0.0.2"},
		},
	}}
	for _, sender := range []string{"example.com", "@example.com"} {
		t.Run(sender, func(t *testing.T) {
			v := NewVerifier(sender, netip.MustParseAddr("192.0.2.1"), "helo.example.net")
			v.SetResolver(resolver)
			got, err := v.Test(context.TODO())
			if got != ResultPass {
				t.Errorf("incorrect result, want=%s, got=%s, err=%v", ResultPass, got, err)
			}
		})
	}
}
