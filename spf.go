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

var discardLogger = slog.New(slog.DiscardHandler)

// Checker checks SPF policies. The zero value is ready to use with the
// system resolver. A Checker is safe for concurrent use, but must not be
// modified while checks are running.
type Checker struct {
	// Resolver looks up DNS records, net.DefaultResolver if nil.
	Resolver Resolver

	// Receiver is the domain name of the host performing the check,
	// used for the %{r} macro and in Received-SPF headers.
	Receiver string

	// LookupLimit is the number of terms causing DNS lookups ("include", "a",
	// "mx", "ptr", "exists" and "redirect") allowed in one check, 10 if <= 0.
	// Exceeding it gives ResultPermError with ErrTooManyLookups.
	// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4
	LookupLimit int

	// Timeout limits each check, 20 seconds if <= 0.
	// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4
	Timeout time.Duration

	// Logger logs the steps of each check at debug level, nothing is logged if nil.
	Logger *slog.Logger
}

const (
	defaultMaxLookups = 10
	defaultTimeout    = 20 * time.Second
)

var defaultChecker Checker

// CheckMailFrom checks the MAIL FROM identity with the zero Checker.
// See Checker.CheckMailFrom.
func CheckMailFrom(ctx context.Context, ip netip.Addr, mailFrom, helo string) *Outcome {
	return defaultChecker.CheckMailFrom(ctx, ip, mailFrom, helo)
}

// CheckHelo checks the HELO identity with the zero Checker.
// See Checker.CheckHelo.
func CheckHelo(ctx context.Context, ip netip.Addr, helo string) *Outcome {
	return defaultChecker.CheckHelo(ctx, ip, helo)
}

// CheckMailFrom checks the MAIL FROM identity of a message from ip.
// mailFrom is the MAIL FROM reverse-path without angle brackets; when it's
// empty, "postmaster@" + helo is checked. helo is the domain of the
// HELO/EHLO command.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-2.4
func (c *Checker) CheckMailFrom(ctx context.Context, ip netip.Addr, mailFrom, helo string) *Outcome {
	local, domain := splitSender(mailFrom, helo)
	return c.newCheck(ip, mailFrom, helo, local, domain).run(ctx, IdentityMailFrom)
}

// CheckHelo checks the HELO identity, i.e. "postmaster@" + helo, which is
// recommended before checking MAIL FROM; a "pass" for HELO may make the
// MAIL FROM check unnecessary. A HELO with an address literal gives ResultNone.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-2.3
func (c *Checker) CheckHelo(ctx context.Context, ip netip.Addr, helo string) *Outcome {
	return c.newCheck(ip, "", helo, "postmaster", helo).run(ctx, IdentityHelo)
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

// check holds the inputs and settings of a single check.
type check struct {
	mailFrom     string // MAIL FROM as given
	sender       string // <sender> as local-part@domain
	senderLocal  string // local-part of <sender>
	senderDomain string // domain of <sender>
	ip           netip.Addr
	helloDomain  string

	resolver    Resolver
	receiver    string
	lookupLimit int
	timeout     time.Duration
	logger      *slog.Logger
}

func (c *Checker) newCheck(ip netip.Addr, mailFrom, helo, senderLocal, senderDomain string) *check {
	ch := &check{
		mailFrom:     mailFrom,
		sender:       senderLocal + "@" + senderDomain,
		senderLocal:  senderLocal,
		senderDomain: senderDomain,
		// IPv4-mapped IPv6 addresses are treated as IPv4
		// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-5
		ip:          ip.Unmap(),
		helloDomain: helo,
		resolver:    c.Resolver,
		receiver:    c.Receiver,
		lookupLimit: c.LookupLimit,
		timeout:     c.Timeout,
		logger:      c.Logger,
	}
	if ch.resolver == nil {
		ch.resolver = net.DefaultResolver
	}
	if ch.lookupLimit <= 0 {
		ch.lookupLimit = defaultMaxLookups
	}
	if ch.timeout <= 0 {
		ch.timeout = defaultTimeout
	}
	if ch.logger == nil {
		ch.logger = discardLogger
	}
	return ch
}

func (ch *check) run(ctx context.Context, identity Identity) *Outcome {
	o := &Outcome{
		Result:   ResultNone,
		Identity: identity,
		Sender:   ch.sender,
		MailFrom: ch.mailFrom,
		ClientIP: ch.ip,
		Helo:     ch.helloDomain,
		Receiver: ch.receiver,
	}
	// a HELO with an address literal is not a valid domain either
	if !isValidDomain(ch.senderDomain) {
		ch.logResult(ctx, o)
		return o
	}

	ctx, cancel := context.WithTimeout(ctx, ch.timeout)
	defer cancel()
	e := &evaluation{check: ch, ctx: ctx}
	o.Result, o.Problem = e.checkHost(ch.senderDomain)
	o.Mechanism = e.mechanism
	if o.Result == ResultFail {
		o.Explanation = e.explanation
	}
	ch.logResult(ctx, o)
	return o
}

func (ch *check) logResult(ctx context.Context, o *Outcome) {
	ch.logger.DebugContext(ctx, "spf: result",
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
func (ch *check) env(domain string) *macroEnv {
	return &macroEnv{
		sender:       ch.sender,
		senderLocal:  ch.senderLocal,
		senderDomain: ch.senderDomain,
		domain:       domain,
		ip:           ch.ip,
		helloDomain:  ch.helloDomain,
		receiver:     ch.receiver,
		now:          time.Now(),
	}
}
