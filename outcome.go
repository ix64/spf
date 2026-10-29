package spf

import (
	"fmt"
	"net/netip"
	"strings"
)

// Identity is the identity checked by SPF.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-2.3
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-2.4
type Identity string

const (
	IdentityMailFrom Identity = "mailfrom"
	IdentityHelo     Identity = "helo"
)

// Outcome is the result of an SPF check with the details behind it.
type Outcome struct {
	Result   Result
	Identity Identity

	// Sender is the <sender> checked, e.g. "postmaster@" + Helo for IdentityHelo,
	// with its domain in A-labels.
	Sender   string
	MailFrom string // MAIL FROM as given to CheckMailFrom, empty for CheckHelo
	ClientIP netip.Addr
	Helo     string // HELO domain, in A-labels
	Receiver string // Checker.Receiver

	// Mechanism is the directive that produced the result, empty if none matched.
	Mechanism string

	// Explanation is the text of the "exp" modifier for ResultFail, empty if none.
	// It's controlled by the sender domain, so it should be shown as is.
	// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-6.2
	Explanation string

	// Problem explains ResultTempError and ResultPermError.
	Problem error
}

// ReceivedSPF returns the value of a Received-SPF header field recording the
// outcome, without the "Received-SPF:" name and without folding.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-9.1
func (o *Outcome) ReceivedSPF() string {
	var sb strings.Builder
	sb.WriteString(replaceControl(string(o.Result)))
	sb.WriteString(" (")
	if o.Receiver != "" {
		sb.WriteString(escapeComment(o.Receiver))
		sb.WriteString(": ")
	}
	sb.WriteString(escapeComment(o.comment()))
	sb.WriteString(")")

	pair := func(key, value string) {
		sb.WriteString(" ")
		sb.WriteString(key)
		sb.WriteString("=")
		sb.WriteString(headerValue(value))
		sb.WriteString(";")
	}
	if o.Receiver != "" {
		pair("receiver", o.Receiver)
	}
	pair("client-ip", o.ClientIP.String())
	// a HELO check may happen before MAIL FROM is known
	if o.Identity == IdentityMailFrom || o.MailFrom != "" {
		pair("envelope-from", o.MailFrom)
	}
	if o.Helo != "" {
		pair("helo", o.Helo)
	}
	pair("identity", string(o.Identity))
	if o.Mechanism != "" {
		pair("mechanism", o.Mechanism)
	}
	if o.Problem != nil {
		pair("problem", o.Problem.Error())
	}
	return sb.String()
}

// comment describes the outcome for humans.
func (o *Outcome) comment() string {
	switch o.Result {
	case ResultPass:
		return fmt.Sprintf("domain of %s designates %s as permitted sender", o.Sender, o.ClientIP)
	case ResultFail:
		return fmt.Sprintf("domain of %s does not designate %s as permitted sender", o.Sender, o.ClientIP)
	case ResultSoftFail:
		return fmt.Sprintf("domain of transitioning %s does not designate %s as permitted sender", o.Sender, o.ClientIP)
	case ResultNeutral:
		return fmt.Sprintf("%s is neither permitted nor denied by domain of %s", o.ClientIP, o.Sender)
	case ResultNone:
		return fmt.Sprintf("domain of %s does not designate permitted sender hosts", o.Sender)
	case ResultTempError:
		return fmt.Sprintf("temporary error in processing during lookup of %s", o.Sender)
	case ResultPermError:
		return fmt.Sprintf("permanent error in processing domain of %s", o.Sender)
	default:
		return string(o.Result)
	}
}

// replaceControl replaces control characters with "?". Comments and
// quoted-strings can't hold them, and a CR or LF taken from the MAIL FROM,
// HELO or an error would end the header field, letting it inject others.
func replaceControl(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}

// escapeComment escapes the characters that are special in a comment.
// ref: https://datatracker.ietf.org/doc/html/rfc5322#section-3.2.2
func escapeComment(s string) string {
	return strings.NewReplacer(`\`, `\\`, `(`, `\(`, `)`, `\)`).Replace(replaceControl(s))
}

// headerValue returns s as a dot-atom if possible, else as a quoted-string.
// ref: https://datatracker.ietf.org/doc/html/rfc5322#section-3.2.3
func headerValue(s string) string {
	s = replaceControl(s)
	if isDotAtom(s) {
		return s
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// dot-atom-text = 1*atext *("." 1*atext)
func isDotAtom(s string) bool {
	for _, atom := range strings.Split(s, ".") {
		if atom == "" {
			return false
		}
		for i := 0; i < len(atom); i++ {
			c := atom[i]
			if !isAlpha(c) && !isDigit(c) && !strings.ContainsRune("!#$%&'*+-/=?^_`{|}~", rune(c)) {
				return false
			}
		}
	}
	return true
}
