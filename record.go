package spf

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Record is a parsed SPF record.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.1
type Record struct {
	// Directives in the order they appear in the record.
	Directives []Directive

	// Redirect is the domain-spec of the "redirect" modifier, nil if absent.
	Redirect *MacroString

	// Exp is the domain-spec of the "exp" modifier, nil if absent.
	Exp *MacroString
}

// String returns the record in canonical form, without unknown modifiers.
func (rec *Record) String() string {
	terms := []string{"v=spf1"}
	for _, d := range rec.Directives {
		terms = append(terms, d.String())
	}
	if rec.Redirect != nil {
		terms = append(terms, "redirect="+rec.Redirect.String())
	}
	if rec.Exp != nil {
		terms = append(terms, "exp="+rec.Exp.String())
	}
	return strings.Join(terms, " ")
}

// Directive is a mechanism with its qualifier.
type Directive struct {
	Qualifier Qualifier
	Mechanism Mechanism
}

func (d Directive) String() string {
	if d.Qualifier == QualifierPass {
		return d.Mechanism.String()
	}
	return string(d.Qualifier) + d.Mechanism.String()
}

// Mechanism is one of MechanismAll, MechanismInclude, MechanismA, MechanismMX,
// MechanismPTR, MechanismIP and MechanismExists.
type Mechanism interface {
	fmt.Stringer
	isMechanism()
}

// MechanismAll always matches.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-5.1
type MechanismAll struct{}

// MechanismInclude matches if the SPF record of Domain passes.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-5.2
type MechanismInclude struct {
	Domain MacroString
}

// MechanismA matches if <ip> is in the networks of Domain's address records.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-5.3
type MechanismA struct {
	Domain *MacroString // nil means <domain>
	CIDR   DualCIDR
}

// MechanismMX matches if <ip> is in the networks of Domain's MX hosts.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-5.4
type MechanismMX struct {
	Domain *MacroString // nil means <domain>
	CIDR   DualCIDR
}

// MechanismPTR matches if a validated reverse name of <ip> is in Domain.
// It's not recommended to use.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-5.5
type MechanismPTR struct {
	Domain *MacroString // nil means <domain>
}

// MechanismIP is the "ip4" or "ip6" mechanism, matching if <ip> is in Prefix.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-5.6
type MechanismIP struct {
	Prefix netip.Prefix
}

// MechanismExists matches if Domain has an A record.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-5.7
type MechanismExists struct {
	Domain MacroString
}

// DualCIDR holds the prefix lengths applied to IPv4 and IPv6 addresses.
type DualCIDR struct {
	V4 int
	V6 int
}

var defaultDualCIDR = DualCIDR{V4: 32, V6: 128}

func (c DualCIDR) String() string {
	var s string
	if c.V4 != 32 {
		s += "/" + strconv.Itoa(c.V4)
	}
	if c.V6 != 128 {
		s += "//" + strconv.Itoa(c.V6)
	}
	return s
}

func (MechanismAll) isMechanism()     {}
func (MechanismInclude) isMechanism() {}
func (MechanismA) isMechanism()       {}
func (MechanismMX) isMechanism()      {}
func (MechanismPTR) isMechanism()     {}
func (MechanismIP) isMechanism()      {}
func (MechanismExists) isMechanism()  {}

func (MechanismAll) String() string       { return "all" }
func (m MechanismInclude) String() string { return "include:" + m.Domain.String() }
func (m MechanismA) String() string       { return "a" + optionalDomain(m.Domain) + m.CIDR.String() }
func (m MechanismMX) String() string      { return "mx" + optionalDomain(m.Domain) + m.CIDR.String() }
func (m MechanismPTR) String() string     { return "ptr" + optionalDomain(m.Domain) }
func (m MechanismExists) String() string  { return "exists:" + m.Domain.String() }
func (m MechanismIP) String() string {
	name := "ip6:"
	if m.Prefix.Addr().Is4() {
		name = "ip4:"
	}
	if m.Prefix.IsSingleIP() {
		return name + m.Prefix.Addr().String()
	}
	return name + m.Prefix.String()
}

func optionalDomain(m *MacroString) string {
	if m == nil {
		return ""
	}
	return ":" + m.String()
}

// isSPFRecord reports whether a TXT record is an SPF version 1 record.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-4.5
func isSPFRecord(txt string) bool {
	const version = "v=spf1"
	return len(txt) >= len(version) &&
		strings.EqualFold(txt[:len(version)], version) &&
		(len(txt) == len(version) || txt[len(version)] == ' ')
}

// Parse parses an SPF record such as "v=spf1 mx -all".
// Any syntax error in the record is returned,
// which check_host() treats as "permerror".
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-4.6
func Parse(txt string) (*Record, error) {
	if !isSPFRecord(txt) {
		return nil, errors.New("spf: not an SPF record")
	}

	rec := &Record{}
	// record = version terms *SP
	// terms  = *( 1*SP ( directive / modifier ) )
	for _, term := range strings.Split(txt, " ")[1:] {
		if term == "" {
			continue
		}
		if err := rec.parseTerm(term); err != nil {
			return nil, fmt.Errorf("spf: invalid term %q: %w", term, err)
		}
	}
	return rec, nil
}

func (rec *Record) parseTerm(term string) error {
	name, value, isModifier := splitModifier(term)
	if !isModifier {
		d, err := parseDirective(term)
		if err != nil {
			return err
		}
		rec.Directives = append(rec.Directives, d)
		return nil
	}

	switch name {
	case "redirect":
		// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-6.1
		if rec.Redirect != nil {
			return errors.New("duplicate redirect modifier")
		}
		spec, err := parseDomainSpec(value)
		if err != nil {
			return err
		}
		rec.Redirect = &spec
	case "exp":
		// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-6.2
		if rec.Exp != nil {
			return errors.New("duplicate exp modifier")
		}
		spec, err := parseDomainSpec(value)
		if err != nil {
			return err
		}
		rec.Exp = &spec
	default:
		// unknown modifiers are ignored, but must be syntactically valid
		// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-6
		if _, err := parseMacroString(value); err != nil {
			return err
		}
	}
	return nil
}

// splitModifier splits a modifier term into its lower-cased name and value.
// name = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )
func splitModifier(term string) (name, value string, ok bool) {
	eq := strings.IndexByte(term, '=')
	if eq <= 0 {
		return "", "", false
	}
	name = term[:eq]
	if !isAlpha(name[0]) {
		return "", "", false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if !isAlpha(c) && !isDigit(c) && c != '-' && c != '_' && c != '.' {
			return "", "", false
		}
	}
	return strings.ToLower(name), term[eq+1:], true
}

// parseDirective parses a directive = [ qualifier ] mechanism
func parseDirective(term string) (Directive, error) {
	d := Directive{Qualifier: QualifierPass}
	switch q := Qualifier(term[0]); q {
	case QualifierPass, QualifierFail, QualifierSoftFail, QualifierNeutral:
		d.Qualifier = q
		term = term[1:]
	}

	nameEnd := strings.IndexAny(term, ":/")
	if nameEnd < 0 {
		nameEnd = len(term)
	}
	name, rest := strings.ToLower(term[:nameEnd]), term[nameEnd:]

	var err error
	switch name {
	case "all":
		if rest != "" {
			return d, errors.New("unexpected arguments for all")
		}
		d.Mechanism = MechanismAll{}
	case "include":
		var m MechanismInclude
		m.Domain, err = parseRequiredDomainSpec(rest)
		d.Mechanism = m
	case "exists":
		var m MechanismExists
		m.Domain, err = parseRequiredDomainSpec(rest)
		d.Mechanism = m
	case "a":
		var m MechanismA
		m.Domain, m.CIDR, err = parseDomainDualCIDR(rest)
		d.Mechanism = m
	case "mx":
		var m MechanismMX
		m.Domain, m.CIDR, err = parseDomainDualCIDR(rest)
		d.Mechanism = m
	case "ptr":
		var m MechanismPTR
		m.Domain, err = parseOptionalDomainSpec(rest)
		d.Mechanism = m
	case "ip4", "ip6":
		var m MechanismIP
		m.Prefix, err = parseIPNetwork(name == "ip4", rest)
		d.Mechanism = m
	default:
		return d, fmt.Errorf("unknown mechanism %q", name)
	}
	return d, err
}

// parseRequiredDomainSpec parses ":" domain-spec
func parseRequiredDomainSpec(s string) (MacroString, error) {
	if !strings.HasPrefix(s, ":") {
		return MacroString{}, errors.New("missing domain-spec")
	}
	return parseDomainSpec(s[1:])
}

// parseOptionalDomainSpec parses [ ":" domain-spec ]
func parseOptionalDomainSpec(s string) (*MacroString, error) {
	if s == "" {
		return nil, nil
	}
	spec, err := parseRequiredDomainSpec(s)
	if err != nil {
		return nil, err
	}
	return &spec, nil
}

// parseDomainDualCIDR parses [ ":" domain-spec ] [ dual-cidr-length ] for "a" and "mx".
// A domain-spec may contain "/", so the CIDR lengths are taken from the end.
func parseDomainDualCIDR(s string) (*MacroString, DualCIDR, error) {
	cidr := defaultDualCIDR
	var err error

	// dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]
	if i := strings.LastIndex(s, "//"); i >= 0 && isDigits(s[i+2:]) {
		if cidr.V6, err = parseCIDRLength(s[i+2:], 128); err != nil {
			return nil, cidr, err
		}
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '/'); i >= 0 && isDigits(s[i+1:]) {
		if cidr.V4, err = parseCIDRLength(s[i+1:], 32); err != nil {
			return nil, cidr, err
		}
		s = s[:i]
	}

	spec, err := parseOptionalDomainSpec(s)
	return spec, cidr, err
}

// parseIPNetwork parses ":" ip4-network [ ip4-cidr-length ]
// or ":" ip6-network [ ip6-cidr-length ]
func parseIPNetwork(is4 bool, s string) (netip.Prefix, error) {
	if !strings.HasPrefix(s, ":") {
		return netip.Prefix{}, errors.New("missing ip network")
	}
	s = s[1:]

	maxBits := 128
	if is4 {
		maxBits = 32
	}
	bits := maxBits
	if i := strings.IndexByte(s, '/'); i >= 0 {
		var err error
		if bits, err = parseCIDRLength(s[i+1:], maxBits); err != nil {
			return netip.Prefix{}, err
		}
		s = s[:i]
	}

	addr, err := netip.ParseAddr(s)
	if err != nil || addr.Zone() != "" || addr.Is4() != is4 {
		return netip.Prefix{}, fmt.Errorf("invalid ip network %q", s)
	}
	return netip.PrefixFrom(addr, bits).Masked(), nil
}

// parseCIDRLength parses a CIDR length without leading zeros, up to max.
// ip4-cidr-length = "/" ("0" / %x31-39 0*1DIGIT)
// ip6-cidr-length = "/" ("0" / %x31-39 0*2DIGIT)
func parseCIDRLength(s string, max int) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || !isDigits(s) || (len(s) > 1 && s[0] == '0') || n > max {
		return 0, fmt.Errorf("invalid cidr length %q", s)
	}
	return n, nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
