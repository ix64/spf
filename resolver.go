package spf

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/miekg/dns"
)

type DNSResolver interface {
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

var limitExceededDeadline = NewCheckError(ResultTempError, "dns: query limit exceeded (deadline)")
var errInvalidDomain = NewCheckError(ResultPermError, "dns: invalid domain name")

// lookupError converts an error returned by DNSResolver into a *CheckError.
// A name without records maps to ResultNone.
func lookupError(err error) error {
	if err == nil {
		return nil
	}
	var cErr *CheckError
	if errors.As(err, &cErr) {
		return cErr
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return limitExceededDeadline
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return NewCheckError(ResultNone, "dns: "+dnsErr.Error())
	}
	// any other DNS failure is treated as transient
	return WrapCheckError(err, ResultTempError, "dns: lookup failed")
}

func (e *evaluation) lookupTXT(name string) ([]string, error) {
	if _, ok := dns.IsDomainName(name); !ok {
		return nil, errInvalidDomain
	}
	rs, err := e.resolver.LookupTXT(e.ctx, name)
	return rs, lookupError(err)
}

func (e *evaluation) lookupNetIP(network, host string) ([]netip.Addr, error) {
	if _, ok := dns.IsDomainName(host); !ok {
		return nil, errInvalidDomain
	}
	rs, err := e.resolver.LookupNetIP(e.ctx, network, host)
	return rs, lookupError(err)
}

func (e *evaluation) lookupMX(name string) ([]*net.MX, error) {
	if _, ok := dns.IsDomainName(name); !ok {
		return nil, errInvalidDomain
	}
	rs, err := e.resolver.LookupMX(e.ctx, name)
	return rs, lookupError(err)
}

func (e *evaluation) lookupAddr(addr netip.Addr) ([]string, error) {
	rs, err := e.resolver.LookupAddr(e.ctx, addr.String())
	return rs, lookupError(err)
}
