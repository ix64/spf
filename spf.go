package spf

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

//todo: add Received-SPF header generation

// Qualifier for SPF DNS record's directive https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.2
type Qualifier byte

const (
	QualifierPass     Qualifier = '+'
	QualifierFail     Qualifier = '-'
	QualifierSoftFail Qualifier = '~'
	QualifierNeutral  Qualifier = '?'
)

// Result of SPF check https://datatracker.ietf.org/doc/html/rfc7208#section-8
type Result string

const (
	// ResultNone the verifier has no information at all about the authorization
	ResultNone Result = "none"

	// ResultNeutral no definite assertion about the client
	// although a policy for the identity was discovered
	ResultNeutral Result = "neutral"

	// ResultPass the client is authorized
	// to inject mail with the given identity
	ResultPass Result = "pass"

	// ResultFail the client is NOT authorized
	// to use the domain in the given identity
	ResultFail Result = "fail"

	// ResultSoftFail the host is not authorized
	// but is not willing to make a strong policy statement
	ResultSoftFail Result = "softfail"

	// ResultTempError the verifier encountered a transient (generally DNS) error while performing the check
	ResultTempError Result = "temperror"

	// ResultPermError the domain's published records could not be correctly interpreted
	ResultPermError Result = "permerror"
)

var discardLogger = log.New(io.Discard, "", 0)

// NewVerifier creates a new SPF Verifier
// sender is the email address of the sender (we don't check if it's valid)
// ip is the remote IP address of current connection
// helloDomain is the domain of the SMTP HELO command (only used for %{h} macro)
func NewVerifier(sender string, ip netip.Addr, helloDomain string) *Verifier {
	senderLocal, senderDomain := splitSender(sender, helloDomain)
	s := &Verifier{
		sender:       senderLocal + "@" + senderDomain,
		senderLocal:  senderLocal,
		senderDomain: senderDomain,
		// IPv4-mapped IPv6 addresses are treated as IPv4
		// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-5
		ip:          ip.Unmap(),
		helloDomain: helloDomain,
		logger:      discardLogger,
		timeout:     defaultSPFTimeout,
	}
	s.SetResolver(net.DefaultResolver)
	return s
}

// splitSender splits sender into local-part and domain.
// A missing local-part is replaced by "postmaster",
// and an empty domain (null reverse-path) falls back to helloDomain.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-4.3
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-2.4
func splitSender(sender, helloDomain string) (local, domain string) {
	local, domain = "postmaster", sender
	if atIdx := strings.LastIndexByte(sender, '@'); atIdx >= 0 {
		domain = sender[atIdx+1:]
		if atIdx > 0 {
			local = sender[:atIdx]
		}
	}
	if domain == "" {
		domain = helloDomain
	}
	return local, domain
}

// Verifier for SPF Version 1
type Verifier struct {
	sender       string // normalized as local-part@domain
	senderLocal  string // local-part of sender
	senderDomain string // domain of sender
	ip           netip.Addr
	helloDomain  string

	resolver *LimitResolver
	timeout  time.Duration
	logger   *log.Logger
}

func (s *Verifier) SetResolver(resolver DNSResolver) {
	limited, ok := resolver.(*LimitResolver)
	if ok {
		s.resolver = limited
	} else {
		s.resolver = NewLimitResolver(resolver, defaultMaxLookups)
	}
}

func (s *Verifier) SetLogger(logger *log.Logger) {
	s.logger = logger
}

const defaultSPFTimeout = time.Second * 20

func (s *Verifier) SetTimeout(t time.Duration) {
	s.timeout = t
}

func (s *Verifier) Test(ctx context.Context) (Result, error) {
	// for now, we support SMTP HELO with domain only
	// todo: support SMTP HELO with address-literal
	// ref: https://www.rfc-editor.org/rfc/rfc5321#section-4.1.1.1
	if _, ok := dns.IsDomainName(s.helloDomain); !ok {
		return ResultFail, errors.New("hello domain is not a domain")
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	e := &evaluation{Verifier: s, ctx: ctx}
	return e.checkHost(s.senderDomain)
}

// env returns the macro values while checking domain.
func (s *Verifier) env(domain string) *macroEnv {
	return &macroEnv{
		sender:       s.sender,
		senderLocal:  s.senderLocal,
		senderDomain: s.senderDomain,
		domain:       domain,
		ip:           s.ip,
		helloDomain:  s.helloDomain,
	}
}
