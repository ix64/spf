package spf

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/foxcpp/go-mockdns"
)

func TestChecker_CheckHelo(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"mail.example.com.": {
			TXT: []string{"v=spf1 a -all"},
			A:   []string{"192.0.2.1"},
		},
		"example.com.": {
			TXT: []string{"v=spf1 -all"},
		},
	}}
	tests := []struct {
		helo string
		ip   string
		want Result
	}{
		{"mail.example.com", "192.0.2.1", ResultPass},
		{"mail.example.com", "192.0.2.2", ResultFail},
		{"[192.0.2.1]", "192.0.2.1", ResultNone}, // address literal
		{"mail", "192.0.2.1", ResultNone},        // not a FQDN
	}
	for _, tt := range tests {
		t.Run(tt.helo+"/"+tt.ip, func(t *testing.T) {
			c := &Checker{Resolver: resolver}
			o := c.CheckHelo(context.TODO(), netip.MustParseAddr(tt.ip), tt.helo)
			if o.Result != tt.want {
				t.Errorf("CheckHelo() = %s, want %s, problem: %v", o.Result, tt.want, o.Problem)
			}
			if o.Identity != IdentityHelo || o.Sender != "postmaster@"+tt.helo || o.MailFrom != "" {
				t.Errorf("CheckHelo() = %+v, want identity helo, sender postmaster@%s and no MAIL FROM", o, tt.helo)
			}
		})
	}
}

func TestChecker_CheckMailFrom(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"example.com.": {
			TXT: []string{"v=spf1 include:_spf.example.com -all exp=exp.example.com"},
		},
		"_spf.example.com.": {
			TXT: []string{"v=spf1 ip4:192.0.2.0/24 -all exp=ignored.example.com"},
		},
		"exp.example.com.": {
			TXT: []string{"%{c} is not one of %{d}'s hosts, checked by %{r}"},
		},
		"ignored.example.com.": {
			TXT: []string{"included exp must be ignored"},
		},
	}}
	tests := []struct {
		ip              string
		wantResult      Result
		wantMechanism   string
		wantExplanation string
	}{
		{"192.0.2.1", ResultPass, "include:_spf.example.com", ""},
		{"198.51.100.1", ResultFail, "-all", "198.51.100.1 is not one of example.com's hosts, checked by mx.example.net"},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			c := &Checker{Resolver: resolver, Receiver: "mx.example.net"}
			o := c.CheckMailFrom(context.TODO(), netip.MustParseAddr(tt.ip), "user@example.com", "helo.example.org")
			if o.Result != tt.wantResult || o.Mechanism != tt.wantMechanism || o.Explanation != tt.wantExplanation {
				t.Errorf("Check() = (%s, %q, %q), want (%s, %q, %q)",
					o.Result, o.Mechanism, o.Explanation, tt.wantResult, tt.wantMechanism, tt.wantExplanation)
			}
		})
	}
}

func TestOutcome_ReceivedSPF(t *testing.T) {
	tests := []struct {
		name    string
		outcome Outcome
		want    string
	}{
		{
			// https://datatracker.ietf.org/doc/html/rfc7208#section-9.1
			// The mechanism is quoted, unlike in the RFC, since it's not a dot-atom.
			// ref: https://www.rfc-editor.org/errata/eid5843
			"RFC example",
			Outcome{
				Result:    ResultPass,
				Identity:  IdentityMailFrom,
				Sender:    "myname@example.com",
				MailFrom:  "myname@example.com",
				ClientIP:  netip.MustParseAddr("192.0.2.1"),
				Helo:      "foo.example.com",
				Receiver:  "mybox.example.org",
				Mechanism: "ip4:192.0.2.0/24",
			},
			`pass (mybox.example.org: domain of myname@example.com designates 192.0.2.1 as permitted sender)` +
				` receiver=mybox.example.org; client-ip=192.0.2.1; envelope-from="myname@example.com";` +
				` helo=foo.example.com; identity=mailfrom; mechanism="ip4:192.0.2.0/24";`,
		},
		{
			"permerror for helo without receiver",
			Outcome{
				Result:   ResultPermError,
				Identity: IdentityHelo,
				Sender:   "postmaster@helo.example.com",
				ClientIP: netip.MustParseAddr("2001:db8::1"),
				Helo:     "helo.example.com",
				Problem:  errors.New(`invalid term "a:(x)"`),
			},
			// no envelope-from, since a HELO check may happen before MAIL FROM
			`permerror (permanent error in processing domain of postmaster@helo.example.com)` +
				` client-ip="2001:db8::1"; helo=helo.example.com; identity=helo;` +
				` problem="invalid term \"a:(x)\"";`,
		},
		{
			// CR and LF must not end the header field
			"control characters",
			Outcome{
				Result:   ResultFail,
				Identity: IdentityMailFrom,
				Sender:   "a\r\nX-Injected: 1@example.com",
				MailFrom: "a\r\nX-Injected: 1@example.com",
				ClientIP: netip.MustParseAddr("192.0.2.1"),
				Helo:     "mail.example.com\nX-Injected: 2",
			},
			`fail (domain of a??X-Injected: 1@example.com does not designate 192.0.2.1 as permitted sender)` +
				` client-ip=192.0.2.1; envelope-from="a??X-Injected: 1@example.com";` +
				` helo="mail.example.com?X-Injected: 2"; identity=mailfrom;`,
		},
		{
			"comment escaping",
			Outcome{
				Result:   ResultNone,
				Identity: IdentityMailFrom,
				Sender:   `a(b)\c@example.com`,
				MailFrom: `a(b)\c@example.com`,
				ClientIP: netip.MustParseAddr("192.0.2.1"),
			},
			`none (domain of a\(b\)\\c@example.com does not designate permitted sender hosts)` +
				` client-ip=192.0.2.1; envelope-from="a(b)\\c@example.com"; identity=mailfrom;`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.outcome.ReceivedSPF(); got != tt.want {
				t.Errorf("ReceivedSPF() =\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}

func Test_parseExplanation(t *testing.T) {
	env := newTestCheck(&Checker{Receiver: "mx.example.net"}, "user@example.com", netip.MustParseAddr("2001:db8::1"), "helo.example.org").env("example.com")

	m, err := parseExplanation("%{c} is not allowed for %{d}, see %{r} at %{t}")
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.expand(env)
	if err != nil {
		t.Fatal(err)
	}
	want := "2001:db8::1 is not allowed for example.com, see mx.example.net at " +
		strconv.FormatInt(env.now.Unix(), 10)
	if got != want {
		t.Errorf("expand() = %q, want %q", got, want)
	}

	// c, r, t and spaces are only allowed in explanation strings
	for _, s := range []string{"%{c}.example.com", "%{r}.example.com", "%{t}.example.com", "a b.example.com"} {
		if _, err := parseDomainSpec(s); err == nil {
			t.Errorf("parseDomainSpec(%q) expected error", s)
		}
	}
	if _, err := parseExplanation("caf\xc3\xa9"); err == nil {
		t.Error("parseExplanation() expected error for non-ASCII text")
	}
}

func TestChecker_Logger(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"example.com.": {
			TXT: []string{"v=spf1 redirect=_spf.example.com"},
		},
		"_spf.example.com.": {
			TXT: []string{"v=spf1 ip4:192.0.2.0/24 -all exp=exp.example.com"},
		},
		"exp.example.com.": {
			TXT: []string{"%{i} is not allowed"},
		},
	}}
	check := func(level slog.Level) string {
		var buf bytes.Buffer
		// leave out the time and the durations, which vary
		handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
			Level: level,
			ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
				if a.Key == slog.TimeKey || a.Key == "duration" {
					return slog.Attr{}
				}
				return a
			},
		})
		c := &Checker{Resolver: resolver, Logger: slog.New(handler)}
		c.CheckMailFrom(context.TODO(), netip.MustParseAddr("198.51.100.1"), "user@example.com", "helo.example.org")
		return buf.String()
	}
	const tags = "identity=mailfrom sender=user@example.com ip=198.51.100.1"

	debug := check(slog.LevelDebug)
	for _, want := range []string{
		`level=DEBUG msg="spf: lookup" ` + tags + ` type=TXT name=example.com records=1` + "\n",
		`level=DEBUG msg="spf: record" ` + tags + ` domain=example.com record="v=spf1 redirect=_spf.example.com"`,
		`level=DEBUG msg="spf: redirect" ` + tags + ` domain=example.com target=_spf.example.com`,
		`level=DEBUG msg="spf: mechanism" ` + tags + ` domain=_spf.example.com mechanism=ip4:192.0.2.0/24 matched=false`,
		`level=DEBUG msg="spf: mechanism" ` + tags + ` domain=_spf.example.com mechanism=-all matched=true`,
		`level=DEBUG msg="spf: lookup" ` + tags + ` type=TXT name=exp.example.com records=1` + "\n",
		`level=INFO msg="spf: result" ` + tags + ` result=fail mechanism=-all explanation="198.51.100.1 is not allowed" lookups=1 void_lookups=0` + "\n",
	} {
		if !strings.Contains(debug, want) {
			t.Errorf("debug log does not contain %s\nlog:\n%s", want, debug)
		}
	}
	if strings.Contains(debug, "error=") {
		t.Errorf("log contains an error attribute:\n%s", debug)
	}

	// the info level only has the result
	info := check(slog.LevelInfo)
	if strings.Count(info, "\n") != 1 || !strings.Contains(info, `level=INFO msg="spf: result" `+tags) {
		t.Errorf("info log = %s, want only the result", info)
	}

	// a nil logger disables logging
	c := &Checker{Resolver: resolver}
	c.CheckMailFrom(context.TODO(), netip.MustParseAddr("198.51.100.1"), "user@example.com", "helo.example.org")
}

// BenchmarkChecker_CheckMailFrom measures a check with logging disabled.
func BenchmarkChecker_CheckMailFrom(b *testing.B) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"example.com.":      {TXT: []string{"v=spf1 include:_spf.example.com a:mail.example.com ip4:203.0.113.0/24 -all"}},
		"_spf.example.com.": {TXT: []string{"v=spf1 ip4:198.51.100.0/24 ip4:198.51.101.0/24 -all"}},
		"mail.example.com.": {A: []string{"203.0.113.9"}},
	}}
	c := &Checker{Resolver: resolver}
	ip := netip.MustParseAddr("192.0.2.1")
	b.ReportAllocs()
	for b.Loop() {
		c.CheckMailFrom(context.Background(), ip, "user@example.com", "mail.example.org")
	}
}
