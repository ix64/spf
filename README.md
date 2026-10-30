# Go SPF Validator

[![Go Reference](https://pkg.go.dev/badge/github.com/ix64/spf.svg)](https://pkg.go.dev/github.com/ix64/spf)
[![CI](https://github.com/ix64/spf/actions/workflows/ci.yml/badge.svg)](https://github.com/ix64/spf/actions/workflows/ci.yml)

- Implements [RFC 7208](https://datatracker.ietf.org/doc/html/rfc7208), passing all cases of the
  [RFC 7208 test suite](testdata/pyspf-rfc7208-tests.yml) of the OpenSPF project, as maintained
  by [pyspf](https://github.com/sdgathman/pyspf), and pyspf's [own tests](testdata/pyspf-tests.yml)
  except two for a modifier of SPF drafts
- Checks both the MAIL FROM and HELO identities, with `exp=` explanations
  and `Received-SPF` headers
- Accepts internationalized domain names, converted to A-labels per
  [RFC 8616](https://datatracker.ietf.org/doc/html/rfc8616)
- Supports Go 1.25+

## Install

```bash
go get github.com/ix64/spf
```

## Usage

```go
import "github.com/ix64/spf"

o := spf.CheckMailFrom(ctx, netip.MustParseAddr("192.0.2.1"), "user@example.com", "mail.example.com")
switch o.Result {
case spf.ResultFail:
	// reject, o.Explanation may hold the sender domain's explanation
case spf.ResultTempError:
	// try again later
}
header := "Received-SPF: " + o.ReceivedSPF()
```

`spf.CheckHelo` checks the HELO identity the same way. How to act on each result is described in
[section 8 of RFC 7208](https://datatracker.ietf.org/doc/html/rfc7208#section-8); when rejecting
mail, [RFC 7372](https://datatracker.ietf.org/doc/html/rfc7372) recommends the enhanced status
codes 5.7.23 for `fail`, and 4.7.24 or 5.7.24 for `temperror` or `permerror`.

To change the settings, create a `Checker` once and share it; it's safe for concurrent use:

```go
checker := &spf.Checker{
	Resolver:    resolver,         // net.DefaultResolver if nil
	Receiver:    "mx.example.net", // for %{r} and Received-SPF
	LookupLimit: 10,               // terms causing DNS lookups per check, 10 if <= 0
	Timeout:     20 * time.Second, // per check, 20 seconds if <= 0
	Logger:      slog.Default(),   // results at info level, steps and DNS lookups at debug
}
o := checker.CheckMailFrom(ctx, ip, mailFrom, helo)
```

A custom `Resolver` gets names fully qualified, with a trailing dot. Like `net.Resolver`, it must
report a name that doesn't exist or has no records of the type as a `*net.DNSError` with
`IsNotFound` set; any other error gives `temperror`.

`Outcome.Problem` explains a `temperror` or `permerror`, naming each `include` and `redirect`
on the way to the cause. It can be matched with `errors.Is` against `spf.ErrTooManyLookups`,
`spf.ErrTooManyVoidLookups`, `spf.ErrTooManyMX`, `spf.ErrMultipleRecords`, `spf.ErrNoRecord`,
`context.DeadlineExceeded` or `context.Canceled`.

`Parse` parses a record without any DNS lookups, e.g. to validate an SPF record before publishing it:

```go
rec, err := spf.Parse("v=spf1 mx include:_spf.example.com -all")
```

## License

[MIT](LICENSE)
