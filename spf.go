package spf

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

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

var discardLogger = slog.New(discardHandler{})

// discardHandler drops every record, like slog.DiscardHandler of Go 1.24.
type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (h discardHandler) WithAttrs([]slog.Attr) slog.Handler      { return h }
func (h discardHandler) WithGroup(string) slog.Handler           { return h }

// NewVerifier creates a new SPF Verifier
// sender is the email address of the sender (we don't check if it's valid)
// ip is the remote IP address of current connection
// helloDomain is the domain of the SMTP HELO/EHLO command
func NewVerifier(sender string, ip netip.Addr, helloDomain string) *Verifier {
	senderLocal, senderDomain := splitSender(sender, helloDomain)
	s := &Verifier{
		mailFrom:     sender,
		sender:       senderLocal + "@" + senderDomain,
		senderLocal:  senderLocal,
		senderDomain: senderDomain,
		// IPv4-mapped IPv6 addresses are treated as IPv4
		// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-5
		ip:          ip.Unmap(),
		helloDomain: helloDomain,
		logger:      discardLogger,
		timeout:     defaultSPFTimeout,
		lookupLimit: defaultMaxLookups,
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

// Verifier for SPF Version 1.
// A Verifier is not modified by checks, so it can be used by several goroutines
// once it's configured.
type Verifier struct {
	mailFrom     string // sender as given
	sender       string // normalized as local-part@domain
	senderLocal  string // local-part of sender
	senderDomain string // domain of sender
	ip           netip.Addr
	helloDomain  string

	resolver    DNSResolver
	timeout     time.Duration
	logger      *slog.Logger
	lookupLimit int
	receiver    string
}

func (s *Verifier) SetResolver(resolver DNSResolver) {
	s.resolver = resolver
}

// defaultMaxLookups is the number of terms causing DNS lookups during SPF evaluation
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4
const defaultMaxLookups = 10

// SetLookupLimit sets the number of terms causing DNS lookups
// ("include", "a", "mx", "ptr", "exists" and "redirect") allowed in one check.
// If this limit is exceeded the result is ResultPermError.
// A limit <= 0 restores the default of 10.
func (s *Verifier) SetLookupLimit(limit int) {
	if limit <= 0 {
		limit = defaultMaxLookups
	}
	s.lookupLimit = limit
}

// SetLogger sets the logger for the steps of each check, logged at debug level.
// A nil logger disables logging, which is the default.
func (s *Verifier) SetLogger(logger *slog.Logger) {
	if logger == nil {
		logger = discardLogger
	}
	s.logger = logger
}

const defaultSPFTimeout = time.Second * 20

func (s *Verifier) SetTimeout(t time.Duration) {
	s.timeout = t
}

// SetReceiver sets the domain name of the host performing the check,
// used for the %{r} macro and in Received-SPF headers.
func (s *Verifier) SetReceiver(receiver string) {
	s.receiver = receiver
}

// Test checks the MAIL FROM identity, returning the result and the problem
// behind ResultTempError or ResultPermError. Use Check for the full Outcome.
func (s *Verifier) Test(ctx context.Context) (Result, error) {
	o := s.Check(ctx)
	return o.Result, o.Problem
}

// Check checks the MAIL FROM identity.
// When the MAIL FROM is empty, this checks "postmaster@" + helloDomain.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-2.4
func (s *Verifier) Check(ctx context.Context) *Outcome {
	return s.check(ctx, IdentityMailFrom)
}

// CheckHelo checks the HELO identity, which is recommended before checking
// MAIL FROM; a "pass" for HELO may make the MAIL FROM check unnecessary.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-2.3
func (s *Verifier) CheckHelo(ctx context.Context) *Outcome {
	return s.check(ctx, IdentityHelo)
}

func (s *Verifier) check(ctx context.Context, identity Identity) *Outcome {
	v := s
	if identity == IdentityHelo {
		helo := *s
		helo.senderLocal, helo.senderDomain = "postmaster", s.helloDomain
		helo.sender = helo.senderLocal + "@" + helo.senderDomain
		v = &helo
	}

	o := &Outcome{
		Result:   ResultNone,
		Identity: identity,
		Sender:   v.sender,
		MailFrom: s.mailFrom,
		ClientIP: s.ip,
		Helo:     s.helloDomain,
		Receiver: s.receiver,
	}
	// a HELO with an address literal is not a valid domain either
	if !isValidDomain(v.senderDomain) {
		s.logResult(ctx, o)
		return o
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	e := &evaluation{Verifier: v, ctx: ctx}
	o.Result, o.Problem = e.checkHost(v.senderDomain)
	o.Mechanism = e.mechanism
	if o.Result == ResultFail {
		o.Explanation = e.explanation
	}
	s.logResult(ctx, o)
	return o
}

func (s *Verifier) logResult(ctx context.Context, o *Outcome) {
	s.logger.DebugContext(ctx, "spf: result",
		"identity", string(o.Identity), "sender", o.Sender, "ip", o.ClientIP.String(),
		"result", string(o.Result), "mechanism", o.Mechanism, errAttr(o.Problem))
}

// isValidDomain reports whether domain is a well-formed multi-label domain name,
// check_host() returns "none" immediately otherwise.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-4.3
func isValidDomain(domain string) bool {
	domain = strings.TrimSuffix(domain, ".")
	if _, ok := dns.IsDomainName(domain); !ok {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
	}
	return true
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
		receiver:     s.receiver,
		now:          time.Now(),
	}
}
