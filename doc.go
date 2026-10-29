// Package spf checks the Sender Policy Framework (SPF) of email senders,
// as specified by RFC 7208.
//
// SPF lets a domain publish, in a DNS TXT record, which hosts may send
// mail using that domain. A receiving mail server checks the MAIL FROM
// identity, and optionally the HELO identity, against the IP address of the
// connecting client:
//
//	o := spf.CheckMailFrom(ctx, clientIP, "user@example.com", "mail.example.com")
//	if o.Result == spf.ResultFail {
//		// the domain says the client may not send its mail
//	}
//
// Internationalized domain names may be given with U-labels; they are
// converted to A-labels as RFC 8616 requires.
//
// CheckMailFrom and CheckHelo use the zero Checker, i.e. the system resolver
// and the default limits. To use another resolver, set the receiver name or
// log the checks, create a Checker once and share it; it is safe for
// concurrent use.
//
// The Outcome of a check holds the Result, the mechanism that produced it,
// the domain's explanation of a ResultFail, and the Problem behind a
// ResultTempError or ResultPermError, which can be matched with errors.Is
// against the Err variables of this package. Outcome.ReceivedSPF formats a
// Received-SPF header field recording the check. How to act on each result
// is described in section 8 of RFC 7208; when rejecting mail, RFC 7372
// recommends the enhanced status codes 5.7.23 for ResultFail, and 4.7.24 or
// 5.7.24 for ResultTempError or ResultPermError.
//
// Parse parses an SPF record without any DNS lookups, e.g. to validate a
// record before publishing it.
//
// The implementation passes the RFC 7208 test suite of the OpenSPF project,
// as maintained by pyspf.
package spf
