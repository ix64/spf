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

	voidLookups int // lookups that returned no records
}

// maxVoidLookups is the number of lookups allowed to return no records.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4
const maxVoidLookups = 2

var limitExceededVoid = NewCheckError(ResultPermError, "dns: void lookup limit exceeded")

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

	env := e.env(domain)
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
		target := rec.Redirect.expandDomain(env)
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
	txts, err := e.resolver.LookupTXT(e.ctx, domain)
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
	case MechanismInclude:
		return e.matchInclude(m.Domain.expandDomain(env))
	case MechanismA:
		return e.matchA(targetName(m.Domain, env), m.CIDR)
	case MechanismMX:
		return e.matchMX(targetName(m.Domain, env), m.CIDR)
	case MechanismPTR:
		return e.matchPTR(targetName(m.Domain, env))
	case MechanismIP:
		return m.Prefix.Contains(e.ip), nil
	case MechanismExists:
		return e.matchExists(m.Domain.expandDomain(env))
	default: // should not happen
		return false, NewCheckError(ResultPermError, fmt.Sprintf("unknown mechanism %T", m))
	}
}

// targetName returns the expanded domain-spec, or <domain> if it's absent.
func targetName(spec *MacroString, env *macroEnv) string {
	if spec == nil {
		return env.domain
	}
	return spec.expandDomain(env)
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
	return e.resolver.LookupNetIP(e.ctx, network, host)
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
	mxs, err := e.resolver.LookupMX(e.ctx, host)
	if void, err := e.checkVoid(len(mxs), err); void || err != nil {
		return false, err
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

// maxPTRNames is the number of PTR names used, the rest are ignored.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4
const maxPTRNames = 10

// matchPTR processes a mechanism "ptr".
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-5.5
func (e *evaluation) matchPTR(target string) (bool, error) {
	names, err := e.resolver.LookupAddr(e.ctx, e.ip.String())
	if void, err := e.checkVoid(len(names), err); void || err != nil {
		// a DNS error on the PTR lookup makes the mechanism fail to match
		if isLimitExceeded(err) {
			return false, err
		}
		return false, nil
	}
	if len(names) > maxPTRNames {
		names = names[:maxPTRNames]
	}

	for _, name := range names {
		if !isSubdomain(name, target) {
			continue
		}
		addrs, err := e.lookupAddrs(name)
		if void, err := e.checkVoid(len(addrs), err); void || err != nil {
			if isLimitExceeded(err) {
				return false, err
			}
			continue
		}
		for _, addr := range addrs {
			if addr.Unmap() == e.ip {
				return true, nil
			}
		}
	}
	return false, nil
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
	addrs, err := e.resolver.LookupNetIP(e.ctx, "ip4", host)
	if void, err := e.checkVoid(len(addrs), err); void || err != nil {
		return false, err
	}
	return true, nil
}
