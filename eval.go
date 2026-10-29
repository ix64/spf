package spf

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// evaluation holds the state of a single SPF check.
type evaluation struct {
	*Verifier
	ctx context.Context

	lookups     int // terms that caused DNS lookups
	voidLookups int // lookups that returned no records

	ptrNames     []string // validated domain names of <ip>, for %{p}
	ptrNamesDone bool
}

// maxVoidLookups is the number of lookups allowed to return no records.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4
const maxVoidLookups = 2

// maxMXNames is the number of MX names allowed for a "mx" mechanism.
// maxPTRNames is the number of PTR names used, the rest are ignored.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4
const (
	maxMXNames  = 10
	maxPTRNames = 10
)

var limitExceededAmount = NewCheckError(ResultPermError, "dns: query limit exceeded (amount)")
var limitExceededVoid = NewCheckError(ResultPermError, "dns: void lookup limit exceeded")
var limitExceededMX = NewCheckError(ResultPermError, "dns: too many MX records")

// resultOf returns the SPF result carried by err.
func resultOf(err error) Result {
	var cErr *CheckError
	if errors.As(err, &cErr) {
		return cErr.result
	}
	return ResultPermError
}

// isNotFound reports whether err means the queried name has no records.
func isNotFound(err error) bool {
	return resultOf(err) == ResultNone
}

// isLimitExceeded reports whether err means the evaluation must stop.
func isLimitExceeded(err error) bool {
	return errors.Is(err, limitExceededAmount) ||
		errors.Is(err, limitExceededDeadline) ||
		errors.Is(err, limitExceededVoid)
}

// countLookup counts a term that causes DNS lookups,
// and returns an error once there are more than the lookup limit.
func (e *evaluation) countLookup() error {
	e.lookups++
	if e.lookups > e.lookupLimit {
		return limitExceededAmount
	}
	return nil
}

// checkVoid classifies a lookup that returned n records with err.
// void reports whether it returned no records, which counts toward the
// void lookup limit; the error is set once the limit is exceeded.
func (e *evaluation) checkVoid(n int, err error) (void bool, _ error) {
	if err != nil && !isNotFound(err) {
		return false, err
	}
	if err == nil && n > 0 {
		return false, nil
	}
	e.voidLookups++
	if e.voidLookups > maxVoidLookups {
		return true, limitExceededVoid
	}
	return true, nil
}

func (q Qualifier) result() Result {
	switch q {
	case QualifierFail:
		return ResultFail
	case QualifierSoftFail:
		return ResultSoftFail
	case QualifierNeutral:
		return ResultNeutral
	default:
		return ResultPass
	}
}

// envFor returns the macro values while checking domain.
func (e *evaluation) envFor(domain string) *macroEnv {
	env := e.env(domain)
	env.validatedName = func() (string, error) {
		return e.validatedName(domain)
	}
	return env
}

// checkHost checks the SPF record on the given domain
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-4
func (e *evaluation) checkHost(domain string) (Result, error) {
	rec, err := e.lookupRecord(domain)
	if err != nil {
		return resultOf(err), err
	}
	if rec == nil {
		return ResultNone, nil
	}

	env := e.envFor(domain)
	for _, d := range rec.Directives {
		e.logger.Printf("mechanism start(%s)", d)
		matched, err := e.match(d.Mechanism, env)
		e.logger.Printf("mechanism result(%s): %v, %v", d, matched, err)
		if err != nil {
			return resultOf(err), err
		}
		if matched {
			return d.Qualifier.result(), nil
		}
	}

	if rec.Exp != nil {
		// modifier "exp" (explanation)
		// https://datatracker.ietf.org/doc/html/rfc7208#section-6.2
		e.logger.Println("modifier(exp): ignored") // we are not supporting it for now
	}

	// If all mechanisms fail to match, and a "redirect" modifier is present
	// https://datatracker.ietf.org/doc/html/rfc7208#section-6.1
	if rec.Redirect != nil {
		if err := e.countLookup(); err != nil {
			return resultOf(err), err
		}
		target, err := rec.Redirect.expandDomain(env)
		if err != nil {
			return resultOf(err), err
		}
		e.logger.Printf("modifier(redirect): %s", target)
		result, err := e.checkHost(target)
		// if no SPF record is found, or if the <target-name> is malformed,
		// the result is a "permerror" rather than "none".
		if result == ResultNone {
			return ResultPermError, fmt.Errorf("spf: record not found on redirect host: %s", target)
		}
		return result, err
	}
	return ResultNeutral, nil
}

// lookupRecord returns the SPF record of domain, or nil if there is none.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-4.4
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-4.5
func (e *evaluation) lookupRecord(domain string) (*Record, error) {
	txts, err := e.lookupTXT(domain)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	var records []string
	for _, txt := range txts {
		if isSPFRecord(txt) {
			records = append(records, txt)
		}
	}
	switch len(records) {
	case 0:
		return nil, nil
	case 1:
		rec, err := Parse(records[0])
		if err != nil {
			return nil, WrapCheckError(err, ResultPermError, "invalid record on "+domain)
		}
		return rec, nil
	default:
		return nil, NewCheckError(ResultPermError, "multiple records on "+domain)
	}
}

// match reports whether the mechanism matches <ip>.
func (e *evaluation) match(m Mechanism, env *macroEnv) (bool, error) {
	switch m := m.(type) {
	case MechanismAll:
		return true, nil
	case MechanismIP:
		return m.Prefix.Contains(e.ip), nil
	}

	// the other mechanisms cause DNS lookups
	if err := e.countLookup(); err != nil {
		return false, err
	}
	target := env.domain
	if spec := domainSpec(m); spec != nil {
		var err error
		if target, err = spec.expandDomain(env); err != nil {
			return false, err
		}
	}

	switch m := m.(type) {
	case MechanismInclude:
		return e.matchInclude(target)
	case MechanismA:
		return e.matchA(target, m.CIDR)
	case MechanismMX:
		return e.matchMX(target, m.CIDR)
	case MechanismPTR:
		return e.matchPTR(target)
	case MechanismExists:
		return e.matchExists(target)
	default: // should not happen
		return false, NewCheckError(ResultPermError, fmt.Sprintf("unknown mechanism %T", m))
	}
}

// domainSpec returns the domain-spec of a mechanism, nil means <domain>.
func domainSpec(m Mechanism) *MacroString {
	switch m := m.(type) {
	case MechanismInclude:
		return &m.Domain
	case MechanismExists:
		return &m.Domain
	case MechanismA:
		return m.Domain
	case MechanismMX:
		return m.Domain
	case MechanismPTR:
		return m.Domain
	default:
		return nil
	}
}

// matchInclude processes a mechanism "include"
// https://datatracker.ietf.org/doc/html/rfc7208#section-5.2
func (e *evaluation) matchInclude(host string) (bool, error) {
	r, err := e.checkHost(host)
	switch r {
	case ResultPass:
		return true, nil
	case ResultFail, ResultSoftFail, ResultNeutral:
		return false, nil
	case ResultTempError:
		return false, WrapCheckError(err, ResultTempError, "check include host failed")
	case ResultNone:
		return false, NewCheckError(ResultPermError, "include host has no record: "+host)
	default:
		return false, WrapCheckError(err, ResultPermError, "check include host failed")
	}
}

// lookupAddrs returns the addresses of host in the same family as <ip>.
func (e *evaluation) lookupAddrs(host string) ([]netip.Addr, error) {
	network := "ip6"
	if e.ip.Is4() {
		network = "ip4"
	}
	return e.lookupNetIP(network, host)
}

// inNetworks reports whether <ip> is in the network of any address.
func (e *evaluation) inNetworks(addrs []netip.Addr, cidr DualCIDR) bool {
	for _, addr := range addrs {
		addr = addr.Unmap()
		bits := cidr.V6
		if addr.Is4() {
			bits = cidr.V4
		}
		if netip.PrefixFrom(addr, bits).Contains(e.ip) {
			return true
		}
	}
	return false
}

// matchA processes a mechanism "a".
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-5.3
func (e *evaluation) matchA(host string, cidr DualCIDR) (bool, error) {
	addrs, err := e.lookupAddrs(host)
	if void, err := e.checkVoid(len(addrs), err); void || err != nil {
		return false, err
	}
	return e.inNetworks(addrs, cidr), nil
}

// matchMX processes a mechanism "mx".
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-5.4
func (e *evaluation) matchMX(host string, cidr DualCIDR) (bool, error) {
	mxs, err := e.lookupMX(host)
	if void, err := e.checkVoid(len(mxs), err); void || err != nil {
		return false, err
	}
	if len(mxs) > maxMXNames {
		return false, limitExceededMX
	}

	for _, mx := range mxs {
		// a null MX has no host to check
		// ref: https://datatracker.ietf.org/doc/html/rfc7505
		if mx.Host == "" || mx.Host == "." {
			continue
		}
		addrs, err := e.lookupAddrs(mx.Host)
		void, err := e.checkVoid(len(addrs), err)
		if err != nil {
			return false, err
		}
		if !void && e.inNetworks(addrs, cidr) {
			return true, nil
		}
	}
	return false, nil
}

// matchPTR processes a mechanism "ptr".
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-5.5
func (e *evaluation) matchPTR(target string) (bool, error) {
	names, err := e.validatedNames(func(name string) bool {
		return isSubdomain(name, target)
	})
	return len(names) > 0, err
}

// validatedNames returns the validated domain names of <ip>,
// i.e. names whose addresses include <ip>, trying only names accepted by want.
// A DNS error, other than exceeding a limit, only leaves names out.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-5.5
func (e *evaluation) validatedNames(want func(name string) bool) ([]string, error) {
	names, err := e.lookupAddr(e.ip)
	if void, err := e.checkVoid(len(names), err); void || err != nil {
		if isLimitExceeded(err) {
			return nil, err
		}
		return nil, nil
	}
	if len(names) > maxPTRNames {
		names = names[:maxPTRNames]
	}

	var validated []string
	for _, name := range names {
		if !want(name) {
			continue
		}
		addrs, err := e.lookupAddrs(name)
		if void, err := e.checkVoid(len(addrs), err); void || err != nil {
			if isLimitExceeded(err) {
				return nil, err
			}
			continue
		}
		for _, addr := range addrs {
			if addr.Unmap() == e.ip {
				validated = append(validated, name)
				break
			}
		}
	}
	return validated, nil
}

// validatedName returns the value of the %{p} macro while checking domain:
// domain itself if it's validated, else a validated subdomain of it,
// else any validated name, else "unknown".
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-7.3
func (e *evaluation) validatedName(domain string) (string, error) {
	if !e.ptrNamesDone {
		// the PTR lookup counts toward the lookup limit
		if err := e.countLookup(); err != nil {
			return "", err
		}
		names, err := e.validatedNames(func(string) bool { return true })
		if err != nil {
			return "", err
		}
		e.ptrNames, e.ptrNamesDone = names, true
	}

	if len(e.ptrNames) == 0 {
		return "unknown", nil
	}
	for _, name := range e.ptrNames {
		if strings.EqualFold(strings.TrimSuffix(name, "."), strings.TrimSuffix(domain, ".")) {
			return strings.TrimSuffix(name, "."), nil
		}
	}
	for _, name := range e.ptrNames {
		if isSubdomain(name, domain) {
			return strings.TrimSuffix(name, "."), nil
		}
	}
	return strings.TrimSuffix(e.ptrNames[0], "."), nil
}

// isSubdomain reports whether name is parent or a subdomain of it.
func isSubdomain(name, parent string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	parent = strings.ToLower(strings.TrimSuffix(parent, "."))
	return name == parent || strings.HasSuffix(name, "."+parent)
}

// matchExists processes a mechanism "exists"
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-5.7
func (e *evaluation) matchExists(host string) (bool, error) {
	// domain is used for a DNS A RR lookup
	// (even when the connection type is IPv6)
	addrs, err := e.lookupNetIP("ip4", host)
	if void, err := e.checkVoid(len(addrs), err); void || err != nil {
		return false, err
	}
	return true, nil
}
