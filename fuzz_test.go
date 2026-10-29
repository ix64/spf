package spf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
)

// anyResolver answers every name: TXT with the fuzzed record, and fixed
// address, MX and PTR records, so that every mechanism is evaluated.
type anyResolver struct {
	record string
}

func (r anyResolver) LookupTXT(context.Context, string) ([]string, error) {
	return []string{r.record}, nil
}

func (anyResolver) LookupNetIP(_ context.Context, network, _ string) ([]netip.Addr, error) {
	if network == "ip4" {
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	}
	return []netip.Addr{netip.MustParseAddr("2001:db8::1")}, nil
}

func (anyResolver) LookupMX(context.Context, string) ([]*net.MX, error) {
	return []*net.MX{{Host: "mx.example.com.", Pref: 10}}, nil
}

func (anyResolver) LookupAddr(context.Context, string) ([]string, error) {
	return []string{"mail.example.com."}, nil
}

// FuzzCheck evaluates arbitrary records, local-parts and HELO domains.
func FuzzCheck(f *testing.F) {
	for _, seed := range []string{
		"v=spf1 -all",
		"v=spf1 a mx ptr exists:%{i}.%{l1r+}.%{d} include:%{d2} -all exp=%{h}",
		"v=spf1 redirect=%{o}",
		"v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a/24//64 mx:%{d}/16 ?all",
		"v=spf1 exists:%{p}.%{v}.%{ir}.example.com -all",
	} {
		f.Add(seed, "user", "mail.example.org", true)
	}
	f.Add("v=spf1 exists:%{l}.example.com -all", "jörg\r\n", "bücher.example", false)

	f.Fuzz(func(t *testing.T, record, local, helo string, v4 bool) {
		ip := netip.MustParseAddr("2001:db8::1")
		if v4 {
			ip = netip.MustParseAddr("192.0.2.1")
		}
		c := &Checker{Resolver: anyResolver{record}}
		for _, o := range []*Outcome{
			c.CheckMailFrom(context.Background(), ip, local+"@example.com", helo),
			c.CheckHelo(context.Background(), ip, helo),
		} {
			switch o.Result {
			case ResultNone, ResultNeutral, ResultPass, ResultFail, ResultSoftFail:
				if o.Problem != nil {
					t.Fatalf("result %s with problem %v", o.Result, o.Problem)
				}
			case ResultTempError, ResultPermError:
				if o.Problem == nil {
					t.Fatalf("result %s without problem", o.Result)
				}
			default:
				t.Fatalf("invalid result %q", o.Result)
			}
			if _, _, _, err := parseReceivedSPF(o.ReceivedSPF()); err != nil {
				t.Fatalf("invalid Received-SPF %q: %v", o.ReceivedSPF(), err)
			}
		}
	})
}

// FuzzReceivedSPF checks that any outcome gives a well-formed header field
// value on a single line, whose values read back as given.
func FuzzReceivedSPF(f *testing.F) {
	f.Add(uint8(0), "user@example.com", "user@example.com", "mail.example.com", "mx.example.net", "ip4:192.0.2.0/24", "")
	f.Add(uint8(6), `a(b)\c"@example.com`, "a\r\nX-Injected: 1@example.com", "h\nx", "", "", `invalid term "a:(x)"`)

	results := []Result{ResultPass, ResultFail, ResultSoftFail, ResultNeutral, ResultNone, ResultTempError, ResultPermError}
	f.Fuzz(func(t *testing.T, result uint8, sender, mailFrom, helo, receiver, mechanism, problem string) {
		o := Outcome{
			Result:    results[int(result)%len(results)],
			Identity:  IdentityMailFrom,
			Sender:    sender,
			MailFrom:  mailFrom,
			ClientIP:  netip.MustParseAddr("192.0.2.1"),
			Helo:      helo,
			Receiver:  receiver,
			Mechanism: mechanism,
		}
		if problem != "" {
			o.Problem = errors.New(problem)
		}
		h := o.ReceivedSPF()
		gotResult, comment, pairs, err := parseReceivedSPF(h)
		if err != nil {
			t.Fatalf("invalid Received-SPF %q: %v", h, err)
		}
		if gotResult != string(o.Result) {
			t.Errorf("result = %q, want %q", gotResult, o.Result)
		}
		if !strings.Contains(comment, replaceControl(sender)) {
			t.Errorf("comment %q does not name the sender %q", comment, sender)
		}
		for key, want := range map[string]string{
			"envelope-from": mailFrom,
			"helo":          helo,
			"receiver":      receiver,
			"mechanism":     mechanism,
			"problem":       problem,
		} {
			got, ok := pairs[key]
			if want == "" && key != "envelope-from" {
				if ok {
					t.Errorf("%s=%q, want it left out", key, got)
				}
				continue
			}
			if got != replaceControl(want) {
				t.Errorf("%s=%q, want %q", key, got, replaceControl(want))
			}
		}
	})
}

// parseReceivedSPF parses a Received-SPF field value as ReceivedSPF formats
// it: result " (" comment ")" *(" " key "=" value ";"), where value is a
// dot-atom or a quoted-string, and nothing holds a control character.
func parseReceivedSPF(h string) (result, comment string, pairs map[string]string, err error) {
	for _, r := range h {
		if r < 0x20 || r == 0x7f {
			return "", "", nil, fmt.Errorf("control character %q", r)
		}
	}
	result, rest, ok := strings.Cut(h, " (")
	if !ok {
		return "", "", nil, errors.New("no comment")
	}
	comment, rest, err = readEscaped(rest, ')', "(")
	if err != nil {
		return "", "", nil, fmt.Errorf("comment: %w", err)
	}

	pairs = map[string]string{}
	for rest != "" {
		if rest[0] != ' ' {
			return "", "", nil, fmt.Errorf("no space before %q", rest)
		}
		key, value, ok := strings.Cut(rest[1:], "=")
		if !ok {
			return "", "", nil, fmt.Errorf("no value in %q", rest)
		}
		if strings.HasPrefix(value, `"`) {
			value, rest, err = readEscaped(value[1:], '"', "")
			if err != nil {
				return "", "", nil, fmt.Errorf("%s: %w", key, err)
			}
		} else {
			value, rest, _ = strings.Cut(value, ";")
			rest = ";" + rest
			if !isDotAtom(value) {
				return "", "", nil, fmt.Errorf("%s: %q is not a dot-atom", key, value)
			}
		}
		if !strings.HasPrefix(rest, ";") {
			return "", "", nil, fmt.Errorf("%s: no semicolon", key)
		}
		pairs[key] = value
		rest = rest[1:]
	}
	return result, comment, pairs, nil
}

// readEscaped reads s up to an unescaped end, undoing backslash escapes;
// an unescaped character of special is an error.
func readEscaped(s string, end byte, special string) (text, rest string, err error) {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\':
			i++
			if i == len(s) {
				return "", "", errors.New("trailing backslash")
			}
			sb.WriteByte(s[i])
		case c == end:
			return sb.String(), s[i+1:], nil
		case strings.IndexByte(special, c) >= 0:
			return "", "", fmt.Errorf("unescaped %q", c)
		default:
			sb.WriteByte(c)
		}
	}
	return "", "", fmt.Errorf("no closing %q", end)
}
