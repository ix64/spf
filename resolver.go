package spf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// Resolver looks up the DNS records used by SPF. *net.Resolver implements it.
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

func (e *evaluation) lookupTXT(name string) ([]string, error) {
	if err := e.beforeLookup(name); err != nil {
		return nil, err
	}
	rs, err := e.resolver.LookupTXT(e.ctx, name)
	return rs, e.lookupError(err)
}

func (e *evaluation) lookupNetIP(network, host string) ([]netip.Addr, error) {
	if err := e.beforeLookup(host); err != nil {
		return nil, err
	}
	rs, err := e.resolver.LookupNetIP(e.ctx, network, host)
	return rs, e.lookupError(err)
}

func (e *evaluation) lookupMX(name string) ([]*net.MX, error) {
	if err := e.beforeLookup(name); err != nil {
		return nil, err
	}
	rs, err := e.resolver.LookupMX(e.ctx, name)
	return rs, e.lookupError(err)
}

func (e *evaluation) lookupAddr(addr netip.Addr) ([]string, error) {
	if err := e.beforeLookup(""); err != nil {
		return nil, err
	}
	rs, err := e.resolver.LookupAddr(e.ctx, addr.String())
	return rs, e.lookupError(err)
}
