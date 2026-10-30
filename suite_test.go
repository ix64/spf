package spf

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/foxcpp/go-mockdns"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v2"
)

type testSuite struct {
	Description string                    `yaml:"description"`
	Comment     string                    `yaml:"comment"`
	Tests       map[string]testCase       `yaml:"tests"`
	ZoneData    map[string]testZoneRecord `yaml:"zonedata"`
}

// name returns the description, or the first line of the comment.
func (s *testSuite) name() string {
	if s.Description != "" {
		return s.Description
	}
	first, _, _ := strings.Cut(strings.TrimSpace(s.Comment), "\n")
	return first
}

type testCase struct {
	Description string     `yaml:"description"`
	Comment     string     `yaml:"comment"`
	Spec        string     `yaml:"spec"`
	Helo        string     `yaml:"helo"`
	Host        string     `yaml:"host"`
	MailFrom    string     `yaml:"mailfrom"`
	Result      testResult `yaml:"result"`
	Explanation string     `yaml:"explanation"`
}
type testResult []Result

func (t *testResult) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var singleVal Result
	if err := unmarshal(&singleVal); err == nil {
		*t = []Result{singleVal}
		return nil
	}
	var multipleVal []Result
	if err := unmarshal(&multipleVal); err == nil {
		*t = multipleVal
		return nil
	}
	return fmt.Errorf("unable to unmarshal test result")
}

// testZoneRecord holds the records of a name in the test suite zone data.
// SPF records are served as TXT records, unless the name has its own TXT records.
// A TXT record "NONE" means the name has no TXT records.
// "TIMEOUT" means lookups without matching records time out; since the
// mock resolver can only time out a whole name, the name times out
// unless it has TXT records, which is what SPF evaluation looks up.
type testZoneRecord struct {
	mockdns.Zone
	spf     []string
	hasTXT  bool
	timeout bool
}

func (t *testZoneRecord) zone() mockdns.Zone {
	zone := t.Zone
	if !t.hasTXT {
		zone.TXT = t.spf
	}
	if t.timeout && len(zone.TXT) == 0 {
		zone.Err = &net.DNSError{
			Err:       context.DeadlineExceeded.Error(),
			IsTimeout: true,
		}
	}
	return zone
}

func (t *testZoneRecord) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var items []interface{}
	if err := unmarshal(&items); err != nil {
		return err
	}
	for _, item := range items {
		switch item := item.(type) {
		case string:
			if item == "TIMEOUT" {
				t.timeout = true
			}
		case map[interface{}]interface{}:
			if err := t.fillByMap(item); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown item type: %T", item)
		}
	}
	return nil
}
func (t *testZoneRecord) fillByMap(m map[interface{}]interface{}) error {
	for k, v := range m {
		if k == "MX" {
			items, ok := v.([]interface{})
			if !ok {
				return fmt.Errorf("MX value is not a list")
			}
			if len(items) != 2 {
				return fmt.Errorf("MX value is not a list of length 2")
			}
			pref, ok := items[0].(int)
			if !ok {
				return fmt.Errorf("the first item of MX is not an integer")
			}
			host, ok := items[1].(string)
			if !ok {
				return fmt.Errorf("the second item of MX is not a string")
			}
			t.MX = append(t.MX, net.MX{Host: host, Pref: uint16(pref)})
			continue
		}

		str, err := parseRecordValue(v)
		if err != nil {
			return err
		}

		switch k {
		case "SPF":
			t.spf = append(t.spf, str)
		case "TXT":
			t.hasTXT = true
			if str != "NONE" {
				t.TXT = append(t.TXT, str)
			}
		case "A":
			t.A = append(t.A, str)
		case "AAAA":
			t.AAAA = append(t.AAAA, str)
		case "PTR":
			t.PTR = append(t.PTR, str)
		case "CNAME":
			t.CNAME = strings.ToLower(dns.Fqdn(str))
		default:
			return fmt.Errorf("unknown key %s", k)
		}
	}
	return nil
}
func parseRecordValue(i interface{}) (string, error) {
	switch i := i.(type) {
	case string:
		return i, nil
	case []interface{}:
		var val string
		for _, v := range i {
			if vv, ok := v.(string); ok {
				val += vv
			} else {
				return "", fmt.Errorf("unable to parse DNS record value: %T", v)
			}
		}
		return val, nil
	default:
		return "", fmt.Errorf("unknown type: %T", i)
	}
}
func loadTestSuites(path string) ([]testSuite, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	var suites []testSuite
	dec := yaml.NewDecoder(f)
	for {
		var suite testSuite
		if err := dec.Decode(&suite); err != nil {
			if err == io.EOF {
				break
			} else {
				return nil, err
			}
		}
		suites = append(suites, suite)
	}
	return suites, nil
}

// testSuiteFiles are the test suites in testdata, with the cases each one skips
// (test name: reason). A skipped case that passes fails the test, so that the
// list stays accurate.
var testSuiteFiles = []struct {
	file string
	skip map[string]string
}{
	// the RFC 7208 test suite of the OpenSPF project, as maintained by pyspf
	{"testdata/pyspf-rfc7208-tests.yml", nil},
	// ad hoc tests of pyspf, from bug reports
	{"testdata/pyspf-tests.yml", map[string]string{
		// RFC 7208 section 6 requires ignoring unknown modifiers, see
		// "default-modifier-obsolete" in the RFC 7208 test suite
		"default-modifier":       `pyspf compatibility with the "default" modifier of SPF drafts`,
		"default-modifier-harsh": `pyspf compatibility with the "default" modifier of SPF drafts`,
	}},
}

func TestChecker_TestSuite(t *testing.T) {
	for _, f := range testSuiteFiles {
		t.Run(strings.TrimSuffix(filepath.Base(f.file), ".yml"), func(t *testing.T) {
			suites, err := loadTestSuites(f.file)
			if err != nil {
				t.Fatalf("Failed to load test suites: %s", err)
			}
			for _, suite := range suites {
				runTestSuite(t, suite, f.skip)
			}
		})
	}
}

func runTestSuite(t *testing.T, suite testSuite, skip map[string]string) {
	t.Run(suite.name(), func(t *testing.T) {
		r := &mockdns.Resolver{Zones: make(map[string]mockdns.Zone)}
		for s, record := range suite.ZoneData {
			r.Zones[strings.ToLower(dns.Fqdn(s))] = record.zone()
		}
		for tName, tt := range suite.Tests {
			t.Run(tName, func(t *testing.T) {
				c := &Checker{Resolver: lowerCaseResolver{r}}
				o := c.CheckMailFrom(context.TODO(), netip.MustParseAddr(tt.Host), tt.MailFrom, tt.Helo)
				got, err := o.Result, o.Problem

				isOneOfExpect := false
				for _, result := range tt.Result {
					if result == got {
						isOneOfExpect = true
						break
					}
				}
				// "DEFAULT" means no explanation from "exp". The suite writes
				// IPv6 nibbles in upper case, so compare case-insensitively.
				wantExp := tt.Explanation
				if wantExp == "DEFAULT" {
					wantExp = ""
				}
				expOK := tt.Explanation == "" || strings.EqualFold(o.Explanation, wantExp)

				if reason, ok := skip[tName]; ok {
					if isOneOfExpect && expOK {
						t.Errorf("skipped case now passes, remove %q from the skip list", tName)
					} else {
						t.Skipf("%s: wants %v %q, got %s %q", reason, tt.Result, wantExp, got, o.Explanation)
					}
					return
				}
				if !isOneOfExpect {
					t.Errorf("wants %v, got %s", tt.Result, got)
				}
				if !expOK {
					t.Errorf("wants explanation %q, got %q", wantExp, o.Explanation)
				}
				if t.Failed() {
					if err != nil {
						t.Log(err)
					}
					t.Logf("spec: %s, %s ", tt.Spec, tt.Description)
					t.Log(tt.Comment)
				}
			})
		}
	})
}

// lowerCaseResolver makes lookups case-insensitive like DNS,
// for zone data with lower-cased names.
type lowerCaseResolver struct {
	Resolver
}

func (r lowerCaseResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return r.Resolver.LookupTXT(ctx, strings.ToLower(name))
}

func (r lowerCaseResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return r.Resolver.LookupNetIP(ctx, network, strings.ToLower(host))
}

func (r lowerCaseResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return r.Resolver.LookupMX(ctx, strings.ToLower(name))
}

func loadMockResolver(zf string) (*mockdns.Resolver, error) {
	zr, err := os.Open(zf)
	if err != nil {
		return nil, err
	}

	zones := map[string]mockdns.Zone{}
	zp := dns.NewZoneParser(zr, "", "")
	zp.SetDefaultTTL(300)

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		hdr := rr.Header()
		zone, ok := zones[hdr.Name]
		if !ok {
			zone = mockdns.Zone{}
		}

		switch hdr.Rrtype {
		case dns.TypeA:
			rrA := rr.(*dns.A)
			zone.A = append(zone.A, rrA.A.String())
		case dns.TypeAAAA:
			rrAAAA := rr.(*dns.AAAA)
			zone.AAAA = append(zone.AAAA, rrAAAA.AAAA.String())
		case dns.TypeMX:
			rrMX := rr.(*dns.MX)
			zone.MX = append(zone.MX, net.MX{Host: rrMX.Mx, Pref: rrMX.Preference})
		case dns.TypeCNAME:
			rrCNAME := rr.(*dns.CNAME)
			zone.CNAME = rrCNAME.Target
		case dns.TypePTR:
			rrPTR := rr.(*dns.PTR)
			zone.PTR = append(zone.PTR, rrPTR.Ptr)
		default:
			return nil, fmt.Errorf("unexpected TYPE: %s", rr.String())
		}

		zones[hdr.Name] = zone
	}

	if err := zp.Err(); err != nil {
		return nil, err
	}
	return &mockdns.Resolver{Zones: zones}, nil
}

func addMockSPFRecord(resolver *mockdns.Resolver, domain, record string) {
	domain = dns.Fqdn(domain)
	zone, ok := resolver.Zones[domain]
	if !ok {
		zone = mockdns.Zone{}
	}
	zone.TXT = append(zone.TXT, record)
	resolver.Zones[domain] = zone
}

type SPFTestCase struct {
	sender      string
	ip          netip.Addr
	helloDomain string
	want        Result
}

func TestChecker_RFC7208Appendix1(t *testing.T) {

	var cases = []struct {
		spf  string //published records for example.com
		ip   string // <ip> would cause check_host() to return "pass"
		want Result
	}{
		{"v=spf1 +all", "10.0.0.1", ResultPass},

		{"v=spf1 a -all", "192.0.2.10", ResultPass},
		{"v=spf1 a -all", "192.0.2.11", ResultPass},

		// no sending hosts as there are no A RRs for example.org
		{"v=spf1 a:example.org -all", "192.0.2.11", ResultFail},

		{"v=spf1 mx -all", "192.0.2.129", ResultPass},
		{"v=spf1 mx -all", "192.0.2.130", ResultPass},

		{"v=spf1 mx:example.org -all", "192.0.2.140", ResultPass},

		{"v=spf1 mx mx:example.org -all", "192.0.2.129", ResultPass},
		{"v=spf1 mx mx:example.org -all", "192.0.2.130", ResultPass},
		{"v=spf1 mx mx:example.org -all", "192.0.2.140", ResultPass},

		{"v=spf1 mx/30 mx:example.org/30 -all", "192.0.2.128", ResultPass},
		{"v=spf1 mx/30 mx:example.org/30 -all", "192.0.2.131", ResultPass},
		{"v=spf1 mx/30 mx:example.org/30 -all", "192.0.2.141", ResultPass},
		{"v=spf1 mx/30 mx:example.org/30 -all", "192.0.2.143", ResultPass},

		{"v=spf1 ptr -all", "192.0.2.65", ResultPass},
		{"v=spf1 ptr -all", "192.0.2.140", ResultFail},
		{"v=spf1 ptr -all", "10.0.0.4", ResultFail},

		{"v=spf1 ip4:192.0.2.128/28 -all", "192.0.2.65", ResultFail},
		{"v=spf1 ip4:192.0.2.128/28 -all", "192.0.2.129", ResultPass},
	}
	for _, s := range cases {
		t.Run(s.spf, func(t *testing.T) {
			resolver, err := loadMockResolver("./testdata/rfc7208-appendix-a1.zone")
			if err != nil {
				t.Error(err)
			}
			addMockSPFRecord(resolver, "example.com", s.spf)

			c := &Checker{Resolver: resolver}
			o := c.CheckMailFrom(context.TODO(), netip.MustParseAddr(s.ip), "test@example.com", "example.net")
			got, err := o.Result, o.Problem
			if got != s.want {
				t.Errorf("incorrect result, want=%s, got=%s", s.want, got)
				t.Error(err)
			}
		})
	}
}

func TestChecker_RFC7208Appendix2(t *testing.T) {
	resolver, err := loadMockResolver("./testdata/rfc7208-appendix-a1.zone")
	if err != nil {
		t.Error(err)
	}
	addMockSPFRecord(resolver, "example.com", "v=spf1 mx -all")
	addMockSPFRecord(resolver, "example.net", "v=spf1 a -all")
	addMockSPFRecord(resolver, "example.org", "v=spf1 include:example.com include:example.net -all")
	addMockSPFRecord(resolver, "la.example.org", "v=spf1 redirect=example.org")

	ip := netip.MustParseAddr("192.0.2.129")
	c := &Checker{Resolver: resolver}
	o := c.CheckMailFrom(context.TODO(), ip, "test@la.example.org", "example.net")
	got, err := o.Result, o.Problem
	want := ResultPass
	if got != want {
		t.Errorf("incorrect result, want=%s, got=%s", want, got)
		t.Error(err)
	}

}
func TestChecker_RFC7208Appendix3(t *testing.T) {
	resolver, err := loadMockResolver("./testdata/rfc7208-appendix-a3.zone")
	if err != nil {
		t.Error(err)
	}
	addMockSPFRecord(resolver, "example.com", "v=spf1 mx include:mobile-users._spf.%{d} include:remote-users._spf.%{d} -all")
	addMockSPFRecord(resolver, "mobile-users._spf.example.com", "v=spf1 exists:%{l1r+}.%{d}")
	addMockSPFRecord(resolver, "remote-users._spf.example.com", "v=spf1 exists:%{ir}.%{l1r+}.%{d}")

	cases := []SPFTestCase{
		{"mary@example.com", netip.MustParseAddr("192.168.254.11"), "example.net", ResultPass},
		{"joel@example.com", netip.MustParseAddr("192.168.15.16"), "example.net", ResultPass},
	}
	for _, tt := range cases {
		t.Run(tt.sender, func(t *testing.T) {
			c := &Checker{Resolver: resolver}
			o := c.CheckMailFrom(context.TODO(), tt.ip, tt.sender, tt.helloDomain)
			got, err := o.Result, o.Problem
			if got != tt.want {
				t.Errorf("incorrect result, want=%s, got=%s", tt.want, got)
				t.Error(err)
			}
		})

	}

}

func TestChecker_RFC7208Appendix4(t *testing.T) {
	resolver, err := loadMockResolver("./testdata/rfc7208-appendix-a3.zone")
	if err != nil {
		t.Error(err)
	}
	addMockSPFRecord(resolver, "example.com.", "v=spf1 -include:ip4._spf.%{d} -include:ptr._spf.%{d} +all")
	addMockSPFRecord(resolver, "ip4._spf.example.com.", "v=spf1 -ip4:192.0.2.0/24 +all")
	// The RFC example uses "-ptr", whose <target-name> is the <domain> being checked,
	// i.e. "ptr._spf.example.com" when included, so it can never match. Use the
	// fix of erratum 6216, and TXT instead of the SPF RR type as in erratum 4001.
	// ref: https://www.rfc-editor.org/errata/eid6216
	// ref: https://www.rfc-editor.org/errata/eid4001
	addMockSPFRecord(resolver, "ptr._spf.example.com.", "v=spf1 -ptr:example.com +all")

	cases := []SPFTestCase{
		{"mary@example.com", netip.MustParseAddr("192.0.2.10"), "example.net", ResultPass},
		{"joel@example.com", netip.MustParseAddr("192.0.2.11"), "example.net", ResultPass},
		{"joel@example.com", netip.MustParseAddr("192.0.3.10"), "example.net", ResultFail},
	}
	for _, tt := range cases {
		t.Run(tt.sender, func(t *testing.T) {
			c := &Checker{Resolver: resolver}
			o := c.CheckMailFrom(context.TODO(), tt.ip, tt.sender, tt.helloDomain)
			got, err := o.Result, o.Problem
			if got != tt.want {
				t.Errorf("incorrect result, want=%s, got=%s", tt.want, got)
				t.Error(err)
			}
		})

	}

}
