package spf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
)

// evaluation holds the state of a single SPF check.
type evaluation struct {
	*check
	ctx context.Context

	lookups     int // terms that caused DNS lookups
	voidLookups int // lookups that returned no records

	ptrNames     []string // validated domain names of <ip>, for %{p}
	ptrNamesDone bool

	includeDepth int    // records checked by "include", their matches are not the result
	mechanism    string // directive that produced the result
	explanation  string // explanation of a "fail"
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

var limitExceededAmount = wrapCheckError(ErrTooManyLookups, ResultPermError, "")
var limitExceededVoid = wrapCheckError(ErrTooManyVoidLookups, ResultPermError, "")
var limitExceededMX = wrapCheckError(ErrTooManyMX, ResultPermError, "")

// resultOf returns the SPF result carried by err.
// Every error leading to a result is a *checkError, so the fallback is never used.
func resultOf(err error) Result {
	var cErr *checkError
	if errors.As(err, &cErr) {
		return cErr.result
	}
	return ResultPermError
}

// stopsEvaluation reports whether err must end the evaluation, even where
// DNS errors are otherwise ignored, like in "ptr".
func stopsEvaluation(err error) bool {
	return errors.Is(err, ErrTooManyLookups) ||
		errors.Is(err, ErrTooManyVoidLookups) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded)
}

// debug logs a step of the evaluation.
// Callers check e.logSteps first, so no arguments are built when it's off.
func (e *evaluation) debug(msg string, args ...any) {
	e.logger.DebugContext(e.ctx, msg, args...)
}

// errAttr returns an "error" attribute, or an empty one that is not logged for nil.
func errAttr(err error) slog.Attr {
	if err == nil {
		return slog.Attr{}
	}
	return slog.Any("error", err)
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
		if e.logSteps {
			e.debug("spf: record lookup failed", "domain", domain, errAttr(err))
		}
		return resultOf(err), err
	}
	if rec == nil {
		if e.logSteps {
			e.debug("spf: no record", "domain", domain)
		}
		return ResultNone, nil
	}
	if e.logSteps {
		e.debug("spf: record", "domain", domain, "record", rec.String())
	}

	env := e.envFor(domain)
	for _, d := range rec.Directives {
		matched, err := e.match(d.Mechanism, env)
		if e.logSteps {
			e.debug("spf: mechanism", "domain", domain, "mechanism", d.String(), "matched", matched, errAttr(err))
		}
		if err != nil {
			return resultOf(err), err
		}
		if matched {
			result := d.Qualifier.result()
			// "exp" of an included record or of a record redirecting elsewhere is not used
			if e.includeDepth == 0 {
				e.mechanism = d.String()
				if result == ResultFail && rec.Exp != nil {
					e.explanation = e.explain(*rec.Exp, env)
				}
			}
			return result, nil
		}
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
		if e.logSteps {
			e.debug("spf: redirect", "domain", domain, "target", target)
		}
		result, err := e.checkHost(target)
		// if no SPF record is found, or if the <target-name> is malformed,
		// the result is a "permerror" rather than "none".
		if result == ResultNone {
			return ResultPermError, wrapCheckError(ErrNoRecord, ResultPermError, "redirect="+target)
		}
		if err != nil {
			err = wrapCheckError(err, result, "redirect="+target)
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
			return nil, wrapCheckError(err, ResultPermError, domain)
		}
		return rec, nil
	default:
		return nil, wrapCheckError(ErrMultipleRecords, ResultPermError, domain)
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
		// %{s} and %{l} of a non-ASCII local-part can't form a DNS name,
		// such terms do not match anything
		// ref: https://datatracker.ietf.org/doc/html/rfc8616#section-4
		if !isASCII(target) {
			if e.logSteps {
				e.debug("spf: non-ASCII target", "domain", env.domain, "target", target)
			}
			return false, nil
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
		return false, newCheckError(ResultPermError, fmt.Sprintf("unknown mechanism %T", m))
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
	e.includeDepth++
	r, err := e.checkHost(host)
	e.includeDepth--
	switch r {
	case ResultPass:
		return true, nil
	case ResultFail, ResultSoftFail, ResultNeutral:
		return false, nil
	case ResultTempError:
		return false, wrapCheckError(err, ResultTempError, "include:"+host)
	case ResultNone:
		return false, wrapCheckError(ErrNoRecord, ResultPermError, "include:"+host)
	default:
		return false, wrapCheckError(err, ResultPermError, "include:"+host)
	}
}

// explain returns the explanation string of the "exp" modifier,
// or "" if it can't be computed for any reason.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-6.2
func (e *evaluation) explain(spec MacroString, env *macroEnv) string {
	domain, err := spec.expandDomain(env)
	if err != nil {
		return ""
	}
	// the lookup does not count toward the lookup limits
	txts, err := e.lookupTXT(domain)
	if err != nil || len(txts) != 1 {
		if e.logSteps {
			e.debug("spf: no explanation", "domain", domain, "records", len(txts), errAttr(err))
		}
		return ""
	}
	m, err := parseExplanation(txts[0])
	if err != nil {
		if e.logSteps {
			e.debug("spf: invalid explanation", "domain", domain, errAttr(err))
		}
		return ""
	}
	text, err := m.expand(env)
	if err != nil {
		return ""
	}
	return text
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
		if stopsEvaluation(err) {
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
			if stopsEvaluation(err) {
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
