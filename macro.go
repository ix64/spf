package spf

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// MacroString is a parsed macro-string or domain-spec.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-7.1
type MacroString struct {
	raw   string
	parts []macroPart
}

// macroPart is either a literal (letter == 0) or a macro-expand.
type macroPart struct {
	literal string

	letter  byte   // lower-case macro-letter
	escape  bool   // upper-case macro-letter: URL-escape the value
	keep    int    // number of right-hand parts to keep, 0 means all
	reverse bool   // transformer "r"
	delims  string // delimiters to split on, empty means not split
}

func (m MacroString) String() string {
	return m.raw
}

// macroLetters are the macro-letters allowed in a domain-spec.
// "c", "r" and "t" are only allowed in an explanation string.
const (
	macroLetters    = "slodiphv"
	expMacroLetters = macroLetters + "crt"
)

const macroDelimiters = ".-+,/_="

// parseMacroString parses a macro-string.
func parseMacroString(s string) (MacroString, error) {
	return parseMacro(s, false)
}

// parseExplanation parses an explanation string from the TXT record of "exp".
// explain-string = *( macro-string / SP )
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-6.2
func parseExplanation(s string) (MacroString, error) {
	return parseMacro(s, true)
}

func parseMacro(s string, explanation bool) (MacroString, error) {
	letters := macroLetters
	if explanation {
		letters = expMacroLetters
	}
	m := MacroString{raw: s}
	var literal strings.Builder
	flush := func() {
		if literal.Len() > 0 {
			m.parts = append(m.parts, macroPart{literal: literal.String()})
			literal.Reset()
		}
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '%' {
			// macro-literal = %x21-24 / %x26-7E
			if (c < 0x21 || c > 0x7e) && (!explanation || c != ' ') {
				return MacroString{}, fmt.Errorf("invalid character %q in macro-string", c)
			}
			literal.WriteByte(c)
			continue
		}

		i++
		if i >= len(s) {
			return MacroString{}, errors.New("incomplete macro-expand at end of macro-string")
		}
		switch s[i] {
		case '%':
			literal.WriteByte('%')
		case '_':
			literal.WriteByte(' ')
		case '-':
			literal.WriteString("%20")
		case '{':
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				return MacroString{}, errors.New("unterminated macro-expand")
			}
			part, err := parseMacroExpand(s[i+1:i+end], letters)
			if err != nil {
				return MacroString{}, err
			}
			flush()
			m.parts = append(m.parts, part)
			i += end
		default:
			return MacroString{}, fmt.Errorf("invalid macro-expand %q", s[i-1:i+1])
		}
	}
	flush()
	return m, nil
}

// parseMacroExpand parses the content between "%{" and "}".
// macro-letter transformers *delimiter
func parseMacroExpand(s, letters string) (macroPart, error) {
	if s == "" {
		return macroPart{}, errors.New("empty macro-expand")
	}
	letter := s[0]
	part := macroPart{letter: letter | 0x20}
	if strings.IndexByte(letters, part.letter) < 0 {
		return macroPart{}, fmt.Errorf("invalid macro-letter %q", letter)
	}
	part.escape = letter >= 'A' && letter <= 'Z'
	rest := s[1:]

	digits := len(rest) - len(strings.TrimLeft(rest, "0123456789"))
	if digits > 0 {
		n, err := strconv.Atoi(rest[:digits])
		if err != nil || n == 0 {
			return macroPart{}, fmt.Errorf("invalid macro transformer %q", rest[:digits])
		}
		part.keep = n
		rest = rest[digits:]
	}
	if rest != "" && (rest[0] == 'r' || rest[0] == 'R') {
		part.reverse = true
		rest = rest[1:]
	}
	for i := 0; i < len(rest); i++ {
		if strings.IndexByte(macroDelimiters, rest[i]) < 0 {
			return macroPart{}, fmt.Errorf("invalid macro delimiter %q", rest[i])
		}
	}
	part.delims = rest
	if part.delims == "" && (part.keep > 0 || part.reverse) {
		part.delims = "."
	}
	return part, nil
}

// parseDomainSpec parses a domain-spec, which is a macro-string with a domain-end.
// domain-spec = macro-string domain-end
// domain-end  = ( "." toplabel [ "." ] ) / macro-expand
func parseDomainSpec(s string) (MacroString, error) {
	if s == "" {
		return MacroString{}, errors.New("empty domain-spec")
	}
	m, err := parseMacroString(s)
	if err != nil {
		return MacroString{}, err
	}
	if last := m.parts[len(m.parts)-1]; last.letter == 0 && !hasDomainEnd(last.literal) {
		return MacroString{}, fmt.Errorf("invalid domain-end in domain-spec %q", s)
	}
	return m, nil
}

// hasDomainEnd reports whether a literal ends with "." toplabel [ "." ].
func hasDomainEnd(literal string) bool {
	literal = strings.TrimSuffix(literal, ".")
	dot := strings.LastIndexByte(literal, '.')
	return dot >= 0 && isTopLabel(literal[dot+1:])
}

// toplabel = ( *alphanum ALPHA *alphanum ) /
//
//	( 1*alphanum "-" *( alphanum / "-" ) alphanum )
func isTopLabel(s string) bool {
	if s == "" || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	hasAlpha, hasHyphen := false, false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case isAlpha(c):
			hasAlpha = true
		case isDigit(c):
		case c == '-':
			hasHyphen = true
		default:
			return false
		}
	}
	return hasAlpha || hasHyphen
}

// macroEnv holds the values that macro-letters expand to.
type macroEnv struct {
	sender       string // <sender>
	senderLocal  string // local-part of <sender>
	senderDomain string // domain of <sender>
	domain       string // <domain> currently being checked
	ip           netip.Addr
	helloDomain  string
	receiver     string    // domain name of the host performing the check
	now          time.Time // for %{t}

	// validatedName returns the value of %{p}, nil means "unknown".
	validatedName func() (string, error)
}

// expand returns the macro-string with every macro-expand replaced.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-7.3
func (m MacroString) expand(env *macroEnv) (string, error) {
	var sb strings.Builder
	for _, part := range m.parts {
		if part.letter == 0 {
			sb.WriteString(part.literal)
			continue
		}
		value, err := part.expand(env)
		if err != nil {
			return "", err
		}
		sb.WriteString(value)
	}
	return sb.String(), nil
}

// expandDomain expands a domain-spec. When the result is longer than 253
// characters, left-side labels are removed until it fits.
func (m MacroString) expandDomain(env *macroEnv) (string, error) {
	domain, err := m.expand(env)
	if err != nil {
		return "", err
	}
	for len(domain) > 253 {
		dot := strings.IndexByte(domain, '.')
		if dot < 0 {
			break
		}
		domain = domain[dot+1:]
	}
	return domain, nil
}

func (p macroPart) expand(env *macroEnv) (string, error) {
	var value string
	switch p.letter {
	case 's':
		value = env.sender
	case 'l':
		value = env.senderLocal
	case 'o':
		value = env.senderDomain
	case 'd':
		value = env.domain
	case 'i':
		value = formatIPDotNotation(env.ip)
	case 'p':
		// validated domain name of <ip>, its use is discouraged
		// https://datatracker.ietf.org/doc/html/rfc7208#section-7.3
		value = "unknown"
		if env.validatedName != nil {
			var err error
			if value, err = env.validatedName(); err != nil {
				return "", err
			}
		}
	case 'v':
		if env.ip.Is4() {
			value = "in-addr"
		} else {
			value = "ip6"
		}
	case 'h':
		value = env.helloDomain
	case 'c':
		value = env.ip.String()
	case 'r':
		value = env.receiver
		if value == "" {
			value = "unknown"
		}
	case 't':
		value = strconv.FormatInt(env.now.Unix(), 10)
	}

	if p.delims != "" {
		items := strings.FieldsFunc(value, func(r rune) bool {
			return strings.ContainsRune(p.delims, r)
		})
		if p.reverse {
			slices.Reverse(items)
		}
		if p.keep > 0 && p.keep < len(items) {
			items = items[len(items)-p.keep:]
		}
		value = strings.Join(items, ".")
	}

	if p.escape {
		value = urlEscape(value)
	}
	return value, nil
}

// urlEscape escapes every character outside the "unreserved" set of RFC 3986.
func urlEscape(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			sb.WriteByte(c)
		} else {
			fmt.Fprintf(&sb, "%%%02X", c)
		}
	}
	return sb.String()
}

func formatIPDotNotation(ip netip.Addr) string {
	if ip.Is4() {
		return ip.String()
	}

	// For IPv6 addresses, the "i" macro expands to a dot-format address
	// https://datatracker.ietf.org/doc/html/rfc7208#section-7.3
	buf := make([]byte, net.IPv6len*2)
	hex.Encode(buf, ip.AsSlice())

	var sb strings.Builder
	sb.Grow(64)
	for _, c := range buf {
		sb.WriteByte(c)
		sb.WriteByte('.')
	}
	return sb.String()[:63]
}
