# Go SPF Validator

- Implements [RFC 7208](https://datatracker.ietf.org/doc/html/rfc7208), passing all cases of the
  [RFC 7208 test suite](testdata/pyspf-rfc7208-tests.yml) of the OpenSPF project, as maintained
  by [pyspf](https://github.com/sdgathman/pyspf), and pyspf's [own tests](testdata/pyspf-tests.yml)
  except two for a modifier of SPF drafts
- Checks both the MAIL FROM and HELO identities, with `exp=` explanations
  and `Received-SPF` headers
- Accepts internationalized domain names, converted to A-labels per
  [RFC 8616](https://datatracker.ietf.org/doc/html/rfc8616)
- Supports Go 1.24+

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

`spf.CheckHelo` checks the HELO identity the same way.

To change the settings, create a `Checker` once and share it; it's safe for concurrent use:

```go
checker := &spf.Checker{
	Resolver: resolver,         // net.DefaultResolver if nil
	Receiver: "mx.example.net", // for %{r} and Received-SPF
	Logger:   slog.Default(),   // logs each step at debug level
}
o := checker.CheckMailFrom(ctx, ip, mailFrom, helo)
```

`Outcome.Problem` explains a `temperror` or `permerror`, naming each `include` and `redirect`
on the way to the cause. It can be matched with `errors.Is` against `spf.ErrTooManyLookups`,
`spf.ErrTooManyVoidLookups`, `spf.ErrTooManyMX`, `spf.ErrMultipleRecords`, `spf.ErrNoRecord`,
`context.DeadlineExceeded` or `context.Canceled`.

`Parse` parses a record without any DNS lookups, e.g. to validate an SPF record before publishing it:

```go
rec, err := spf.Parse("v=spf1 mx include:_spf.example.com -all")
```
