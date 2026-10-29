package spf

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/foxcpp/go-mockdns"
)

func TestEvaluation_matchMX(t *testing.T) {
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
			ch := newTestCheck(&Checker{Resolver: resolver}, tt.sender, netip.MustParseAddr(tt.ip), tt.helloDomain)
			rec, err := Parse("v=spf1 " + tt.stmt)
			if err != nil {
				t.Fatal(err)
			}
			e := &evaluation{check: ch, ctx: context.TODO()}
			matched, err := e.match(rec.Directives[0].Mechanism, ch.env(ch.senderDomain))
			if (err != nil) != tt.wantErr {
				t.Errorf("match() err = %v, want = %v", err, tt.wantErr)
			}
			if matched != tt.want {
				t.Errorf("match() matched = %v, want = %v", matched, tt.want)
			}
		})
	}

}

// newTestCheck returns the check of the MAIL FROM identity.
func newTestCheck(c *Checker, mailFrom string, ip netip.Addr, helo string) *check {
	local, domain := splitSender(mailFrom, helo)
	return c.newCheck(ip, mailFrom, helo, local, domain)
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
func TestChecker_senderWithoutLocalPart(t *testing.T) {
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
			c := &Checker{Resolver: resolver}
			o := c.CheckMailFrom(context.TODO(), netip.MustParseAddr("192.0.2.1"), sender, "helo.example.net")
			got, err := o.Result, o.Problem
			if got != ResultPass {
				t.Errorf("incorrect result, want=%s, got=%s, err=%v", ResultPass, got, err)
			}
		})
	}
}

// lookups are counted per check, so a resolver can be shared between checks
// a Checker counts lookups per check, so it can be shared by concurrent checks
func TestChecker_shared(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"example.com.": {
			TXT: []string{"v=spf1 a a a a a a a a a a -all"},
			A:   []string{"192.0.2.1"},
		},
	}}
	c := &Checker{Resolver: resolver}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o := c.CheckMailFrom(context.TODO(), netip.MustParseAddr("192.0.2.1"), "test@example.com", "example.net")
			if o.Result != ResultPass {
				t.Errorf("check %d: incorrect result, want=%s, got=%s, err=%v", i, ResultPass, o.Result, o.Problem)
			}
		}()
	}
	wg.Wait()
}

func TestChecker_LookupLimit(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"example.com.": {
			TXT: []string{"v=spf1 a:a.example.com a:b.example.com ip4:192.0.2.1 -all"},
		},
		"a.example.com.": {A: []string{"192.0.2.10"}},
		"b.example.com.": {A: []string{"192.0.2.11"}},
	}}
	tests := []struct {
		limit int
		want  Result
	}{
		{1, ResultPermError},
		{2, ResultPass},
		{0, ResultPass}, // default
	}
	for _, tt := range tests {
		c := &Checker{Resolver: resolver, LookupLimit: tt.limit}
		o := c.CheckMailFrom(context.TODO(), netip.MustParseAddr("192.0.2.1"), "test@example.com", "example.net")
		if got, err := o.Result, o.Problem; got != tt.want {
			t.Errorf("limit %d: incorrect result, want=%s, got=%s, err=%v", tt.limit, tt.want, got, err)
		}
		if tt.want == ResultPermError && !errors.Is(o.Problem, ErrTooManyLookups) {
			t.Errorf("limit %d: problem = %v, want ErrTooManyLookups", tt.limit, o.Problem)
		}
	}
}

// blockingResolver answers TXT lookups only when the context is done.
type blockingResolver struct {
	Resolver
}

func (blockingResolver) LookupTXT(ctx context.Context, _ string) ([]string, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestChecker_problems(t *testing.T) {
	mx := make([]net.MX, 11)
	for i := range mx {
		mx[i] = net.MX{Host: "mx.example.com", Pref: uint16(i)}
	}
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"multiple.example.com.": {TXT: []string{"v=spf1 -all", "v=spf1 +all"}},
		"void.example.com.":     {TXT: []string{"v=spf1 a:x1.example.com a:x2.example.com a:x3.example.com -all"}},
		"mx.example.com.":       {TXT: []string{"v=spf1 mx -all"}, MX: mx, A: []string{"192.0.2.10"}},
		"include.example.com.":  {TXT: []string{"v=spf1 include:none.example.com -all"}},
		"redirect.example.com.": {TXT: []string{"v=spf1 redirect=none.example.com"}},
	}}
	tests := []struct {
		domain   string
		resolver Resolver
		result   Result
		problem  error
	}{
		{"multiple.example.com", resolver, ResultPermError, ErrMultipleRecords},
		{"void.example.com", resolver, ResultPermError, ErrTooManyVoidLookups},
		{"mx.example.com", resolver, ResultPermError, ErrTooManyMX},
		{"include.example.com", resolver, ResultPermError, ErrNoRecord},
		{"redirect.example.com", resolver, ResultPermError, ErrNoRecord},
		{"timeout.example.com", blockingResolver{}, ResultTempError, context.DeadlineExceeded},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			c := &Checker{Resolver: tt.resolver, Timeout: 10 * time.Millisecond}
			o := c.CheckMailFrom(context.TODO(), netip.MustParseAddr("192.0.2.1"), "user@"+tt.domain, "example.net")
			if o.Result != tt.result || !errors.Is(o.Problem, tt.problem) {
				t.Errorf("CheckMailFrom() = (%s, %v), want (%s, %v)", o.Result, o.Problem, tt.result, tt.problem)
			}
		})
	}
}

// the package functions use the zero Checker; a malformed domain needs no DNS lookups
func TestCheckMailFrom(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.1")
	if o := CheckMailFrom(context.TODO(), ip, "user@localhost", "localhost"); o.Result != ResultNone {
		t.Errorf("CheckMailFrom() = %s, want %s, problem: %v", o.Result, ResultNone, o.Problem)
	}
	if o := CheckHelo(context.TODO(), ip, "[192.0.2.1]"); o.Result != ResultNone || o.Identity != IdentityHelo {
		t.Errorf("CheckHelo() = %s %s, want %s %s", o.Result, o.Identity, ResultNone, IdentityHelo)
	}
}

func Test_isValidDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{"example.com.", true},
		{"mail.example.com", true},
		{"localhost", false},
		{"", false},
		{"a..example.com", false},
		{".example.com", false},
		{strings.Repeat("a", 64) + ".example.com", false},
		{strings.Repeat("a", 63) + ".example.com", true},
	}
	for _, tt := range tests {
		if got := isValidDomain(tt.domain); got != tt.want {
			t.Errorf("isValidDomain(%q) = %v, want %v", tt.domain, got, tt.want)
		}
	}
}

// cancelingResolver cancels the context after the first TXT lookup,
// and like mockdns it ignores the context itself.
type cancelingResolver struct {
	*mockdns.Resolver
	cancel context.CancelFunc
}

func (r cancelingResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	defer r.cancel()
	return r.Resolver.LookupTXT(ctx, name)
}

// slowResolver delays every lookup and ignores the context.
type slowResolver struct {
	*mockdns.Resolver
}

func (r slowResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	time.Sleep(5 * time.Millisecond)
	return r.Resolver.LookupNetIP(ctx, network, host)
}

// a done context ends the check with temperror, even where DNS errors are
// otherwise ignored and even if the resolver ignores the context
func TestChecker_stopped(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		// a "ptr" ignoring the error would end in a "fail"
		"ptr.example.com.": {TXT: []string{"v=spf1 ptr -all"}},
		"slow.example.com.": {
			TXT: []string{"v=spf1 a a a a a a a a a a -all"},
			A:   []string{"192.0.2.10"},
		},
	}}
	ip := netip.MustParseAddr("192.0.2.1")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Checker{Resolver: cancelingResolver{resolver, cancel}}
	o := c.CheckMailFrom(ctx, ip, "user@ptr.example.com", "example.net")
	if o.Result != ResultTempError || !errors.Is(o.Problem, context.Canceled) {
		t.Errorf("canceled: CheckMailFrom() = (%s, %v), want (%s, %v)", o.Result, o.Problem, ResultTempError, context.Canceled)
	}

	c = &Checker{Resolver: slowResolver{resolver}, Timeout: 12 * time.Millisecond}
	o = c.CheckMailFrom(context.Background(), ip, "user@slow.example.com", "example.net")
	if o.Result != ResultTempError || !errors.Is(o.Problem, context.DeadlineExceeded) {
		t.Errorf("timeout: CheckMailFrom() = (%s, %v), want (%s, %v)", o.Result, o.Problem, ResultTempError, context.DeadlineExceeded)
	}
}

// problems name each record on the way to the cause
func TestChecker_problemMessage(t *testing.T) {
	resolver := &mockdns.Resolver{Zones: map[string]mockdns.Zone{
		"example.com.":      {TXT: []string{"v=spf1 include:_spf.example.com -all"}},
		"_spf.example.com.": {TXT: []string{"v=spf1 redirect=bad.example.com"}},
		"bad.example.com.":  {TXT: []string{"v=spf1 ip4:192.0.2.1 moo"}},
		"none.example.com.": {TXT: []string{"v=spf1 include:%{d2}.example.org -all"}},
	}}
	tests := []struct {
		domain string
		want   string
	}{
		{"example.com", `include:_spf.example.com: redirect=bad.example.com: bad.example.com: spf: invalid term "moo": unknown mechanism "moo"`},
		{"none.example.com", "include:example.com.example.org: spf: no SPF record"},
	}
	for _, tt := range tests {
		c := &Checker{Resolver: resolver}
		o := c.CheckMailFrom(context.TODO(), netip.MustParseAddr("192.0.2.1"), "user@"+tt.domain, "example.net")
		if o.Problem == nil || o.Problem.Error() != tt.want {
			t.Errorf("%s: problem = %v, want %s", tt.domain, o.Problem, tt.want)
		}
	}
}

func Test_isDomainName(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	name253 := strings.Join([]string{label63, label63, label63, strings.Repeat("b", 61)}, ".")
	tests := []struct {
		name string
		want bool
	}{
		{"example.com", true},
		{"example.com.", true},
		{"localhost", true},
		{".", true},
		{"a b.example.com", true}, // DNS allows any octet
		{"_spf.example.com", true},
		{label63 + ".com", true},
		{name253, true},
		{name253 + ".", true},

		{"", false},
		{"..", false},
		{"bücher.example", false}, // U-labels must be converted first
		{".example.com", false},
		{"a..example.com", false},
		{strings.Repeat("a", 64) + ".com", false},
		{name253 + "b", false},
	}
	for _, tt := range tests {
		if got := isDomainName(tt.name); got != tt.want {
			t.Errorf("isDomainName(%q) = %v, want %v (len %d)", tt.name, got, tt.want, len(tt.name))
		}
	}
}

// recordingResolver records the names looked up.
type recordingResolver struct {
	*mockdns.Resolver
	names []string
}

func (r *recordingResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	r.names = append(r.names, name)
	return r.Resolver.LookupTXT(ctx, name)
}

func (r *recordingResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	r.names = append(r.names, host)
	return r.Resolver.LookupNetIP(ctx, network, host)
}

// internationalized domains are checked with A-labels, and terms with a
// non-ASCII local-part do not match
// ref: https://datatracker.ietf.org/doc/html/rfc8616#section-4
func TestChecker_internationalized(t *testing.T) {
	zones := map[string]mockdns.Zone{
		"xn--bcher-kva.example.":                  {TXT: []string{"v=spf1 exists:%{d}.list.example.net -all"}},
		"xn--bcher-kva.example.list.example.net.": {A: []string{"127.0.0.2"}},
		"local.example.": {TXT: []string{
			"v=spf1 exists:%{l}.a.example.net exists:%{l}.b.example.net exists:%{l}.c.example.net -all",
		}},
	}
	ip := netip.MustParseAddr("192.0.2.1")
	tests := []struct {
		name       string
		check      func(c *Checker) *Outcome
		want       Result
		wantSender string
	}{
		{"MAIL FROM", func(c *Checker) *Outcome {
			return c.CheckMailFrom(context.TODO(), ip, "user@Bücher.example", "mail.example.com")
		}, ResultPass, "user@xn--bcher-kva.example"},
		{"HELO", func(c *Checker) *Outcome {
			return c.CheckHelo(context.TODO(), ip, "bücher.example")
		}, ResultPass, "postmaster@xn--bcher-kva.example"},
		{"invalid label", func(c *Checker) *Outcome {
			return c.CheckMailFrom(context.TODO(), ip, "user@\u0301abc.example", "mail.example.com")
		}, ResultNone, "user@\u0301abc.example"},
		// three void lookups would give permerror
		{"non-ASCII local-part", func(c *Checker) *Outcome {
			return c.CheckMailFrom(context.TODO(), ip, "jörg@local.example", "mail.example.com")
		}, ResultFail, "jörg@local.example"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &recordingResolver{Resolver: &mockdns.Resolver{Zones: zones}}
			o := tt.check(&Checker{Resolver: r})
			if o.Result != tt.want || o.Sender != tt.wantSender {
				t.Errorf("got (%s, %q), want (%s, %q), problem: %v", o.Result, o.Sender, tt.want, tt.wantSender, o.Problem)
			}
			for _, name := range r.names {
				if !isASCII(name) {
					t.Errorf("looked up non-ASCII name %q", name)
				}
			}
		})
	}
}
