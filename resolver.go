package spf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// Resolver looks up the DNS records used by SPF. *net.Resolver implements it.
// Names are given fully qualified, with a trailing dot.
//
// Like net.Resolver, a name that doesn't exist or has no records of the
// type must be reported as a *net.DNSError with IsNotFound set; any other
// error is a temporary failure, giving ResultTempError.
type Resolver interface {
	// LookupTXT returns all TXT records for the given domain.
	LookupTXT(ctx context.Context, name string) ([]string, error)

	// LookupNetIP returns all IP addresses of the given host.
	// If network is "ip", IPv6 and IPv4 addresses are returned.
	// If network is "ip4", only IPv4 addresses are returned.
	// If network is "ip6", only IPv6 addresses are returned.
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)

	// LookupMX returns all MX records (host and priority) for a domain.
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)

	// LookupAddr returns the PTR records (domain) for an IP address.
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// errNotFound means a name doesn't exist or has no records of the type.
var errNotFound = errors.New("no records")

// isNotFound reports whether err means the queried name has no records.
func isNotFound(err error) bool {
	return errors.Is(err, errNotFound)
}

// stopped returns the error ending the evaluation because ctx is done.
func stopped(ctxErr error) error {
	return wrapCheckError(ctxErr, ResultTempError, "spf: check stopped")
}

// beforeLookup returns an error if the evaluation must stop, or if name
// is given and is not a valid domain name.
func (e *evaluation) beforeLookup(name string) error {
	if err := e.ctx.Err(); err != nil {
		return stopped(err)
	}
	if name != "" {
		if !isDomainName(name) {
			return newCheckError(ResultPermError, fmt.Sprintf("invalid domain name %q", name))
		}
	}
	return nil
}

// rooted returns name with a trailing dot, so that the resolver looks up
// only the name itself, without appending the search domains of the
// system's resolver configuration.
func rooted(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

// lookupError classifies an error returned by the Resolver.
func (e *evaluation) lookupError(err error) error {
	if err == nil {
		return nil
	}
	// the resolver may not report why it stopped
	if ctxErr := e.ctx.Err(); ctxErr != nil {
		return stopped(ctxErr)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return stopped(err)
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return fmt.Errorf("%w: %w", errNotFound, err)
	}
	// any other DNS failure is treated as transient
	return wrapCheckError(err, ResultTempError, "")
}

// lookupStart returns the start time of a lookup, if lookups are logged.
func (e *evaluation) lookupStart() time.Time {
	if !e.logSteps {
		return time.Time{}
	}
	return time.Now()
}

// logLookup logs a lookup that returned n records with err.
// A name without records is not logged as an error.
func (e *evaluation) logLookup(typ, name string, n int, err error, start time.Time) {
	if !e.logSteps {
		return
	}
	if isNotFound(err) {
		err = nil
	}
	e.debug("spf: lookup", "type", typ, "name", name, "records", n,
		"duration", time.Since(start), errAttr(err))
}

func (e *evaluation) lookupTXT(name string) ([]string, error) {
	if err := e.beforeLookup(name); err != nil {
		return nil, err
	}
	start := e.lookupStart()
	rs, err := e.resolver.LookupTXT(e.ctx, rooted(name))
	err = e.lookupError(err)
	e.logLookup("TXT", name, len(rs), err, start)
	return rs, err
}

func (e *evaluation) lookupNetIP(network, host string) ([]netip.Addr, error) {
	if err := e.beforeLookup(host); err != nil {
		return nil, err
	}
	start := e.lookupStart()
	rs, err := e.resolver.LookupNetIP(e.ctx, network, rooted(host))
	err = e.lookupError(err)
	typ := "AAAA"
	if network == "ip4" {
		typ = "A"
	}
	e.logLookup(typ, host, len(rs), err, start)
	return rs, err
}

func (e *evaluation) lookupMX(name string) ([]*net.MX, error) {
	if err := e.beforeLookup(name); err != nil {
		return nil, err
	}
	start := e.lookupStart()
	rs, err := e.resolver.LookupMX(e.ctx, rooted(name))
	err = e.lookupError(err)
	e.logLookup("MX", name, len(rs), err, start)
	return rs, err
}

func (e *evaluation) lookupAddr(addr netip.Addr) ([]string, error) {
	if err := e.beforeLookup(""); err != nil {
		return nil, err
	}
	start := e.lookupStart()
	rs, err := e.resolver.LookupAddr(e.ctx, addr.String())
	err = e.lookupError(err)
	e.logLookup("PTR", addr.String(), len(rs), err, start)
	return rs, err
}
