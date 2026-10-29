package spf

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/idna"
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

	// Logger logs the result of each check at info level, and its steps and
	// DNS lookups at debug level. Every event has the "identity", "sender"
	// and "ip" of the check. Nothing is logged if nil.
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
// HELO/EHLO command. Domains may be internationalized, with U-labels.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-2.4
func (c *Checker) CheckMailFrom(ctx context.Context, ip netip.Addr, mailFrom, helo string) *Outcome {
	helo = toASCII(helo)
	local, domain := splitSender(mailFrom, helo)
	return c.newCheck(ip, mailFrom, helo, local, toASCII(domain)).run(ctx, IdentityMailFrom)
}

// CheckHelo checks the HELO identity, i.e. "postmaster@" + helo, which is
// recommended before checking MAIL FROM; a "pass" for HELO may make the
// MAIL FROM check unnecessary. A HELO with an address literal gives ResultNone.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-2.3
func (c *Checker) CheckHelo(ctx context.Context, ip netip.Addr, helo string) *Outcome {
	helo = toASCII(helo)
	return c.newCheck(ip, "", helo, "postmaster", helo).run(ctx, IdentityHelo)
}

// idnaProfile converts internationalized domain names for lookup, like
// idna.Lookup but allowing underscores, which are common in DNS.
var idnaProfile = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.StrictDomainName(false))

// toASCII converts the U-labels of an internationalized domain name to
// A-labels, as SPF requires. A domain that can't be converted is returned
// as is, and is then rejected as malformed.
// ref: https://datatracker.ietf.org/doc/html/rfc8616#section-4
func toASCII(domain string) string {
	if isASCII(domain) {
		return domain
	}
	ascii, err := idnaProfile.ToASCII(domain)
	if err != nil {
		return domain
	}
	return ascii
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
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
	logSteps    bool // debug level is enabled, guards building debug events
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
	// tag every event of the check, only when something is logged
	if ch.logger.Enabled(ctx, slog.LevelInfo) {
		ch.logger = ch.logger.With("identity", string(identity), "sender", ch.sender, "ip", ch.ip.String())
	}
	ch.logSteps = ch.logger.Enabled(ctx, slog.LevelDebug)

	// a HELO with an address literal is not a valid domain either
	if !isValidDomain(ch.senderDomain) {
		ch.logResult(ctx, o, nil)
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
	ch.logResult(ctx, o, e)
	return o
}

// logResult logs the outcome, and the lookups used by e if it's not nil.
func (ch *check) logResult(ctx context.Context, o *Outcome, e *evaluation) {
	if !ch.logger.Enabled(ctx, slog.LevelInfo) {
		return
	}
	attrs := []slog.Attr{slog.String("result", string(o.Result))}
	if o.Mechanism != "" {
		attrs = append(attrs, slog.String("mechanism", o.Mechanism))
	}
	if o.Explanation != "" {
		attrs = append(attrs, slog.String("explanation", o.Explanation))
	}
	if e != nil {
		attrs = append(attrs, slog.Int("lookups", e.lookups), slog.Int("void_lookups", e.voidLookups))
	}
	if o.Problem != nil {
		attrs = append(attrs, slog.Any("error", o.Problem))
	}
	ch.logger.LogAttrs(ctx, slog.LevelInfo, "spf: result", attrs...)
}

// isValidDomain reports whether domain is a well-formed multi-label domain name,
// check_host() returns "none" immediately otherwise.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-4.3
func isValidDomain(domain string) bool {
	return isDomainName(domain) && strings.Contains(strings.TrimSuffix(domain, "."), ".")
}

// isDomainName reports whether s is a domain name that fits in DNS: labels of
// 1 to 63 octets, at most 253 octets without the optional trailing dot.
// Like DNS itself, it allows any ASCII octet in labels; U-labels must be
// converted to A-labels first.
// ref: https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.4
// ref: https://datatracker.ietf.org/doc/html/rfc8616#section-4
func isDomainName(s string) bool {
	if s == "." {
		return true
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 || !isASCII(s) {
		return false
	}
	for label := range strings.SplitSeq(s, ".") {
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
