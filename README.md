# Go SPF Validator

- Implements [RFC 7208](https://datatracker.ietf.org/doc/html/rfc7208), passing all cases of the
  [RFC 7208 test suite](testdata/openspf-rfc7208-tests.yml)
- Checks both the MAIL FROM and HELO identities, with `exp=` explanations
  and `Received-SPF` headers
- Supports Go 1.24+

## Usage

```go
v := spf.NewVerifier("user@example.com", netip.MustParseAddr("192.0.2.1"), "mail.example.com")
v.SetReceiver("mx.example.net") // optional, for %{r} and Received-SPF

o := v.Check(ctx) // MAIL FROM identity; v.CheckHelo(ctx) checks HELO
switch o.Result {
case spf.ResultFail:
	// reject, o.Explanation may hold the sender domain's explanation
case spf.ResultTempError:
	// try again later
}
header := "Received-SPF: " + o.ReceivedSPF()
```

`Parse` parses a record without any DNS lookups, e.g. to validate an SPF record before publishing it:

```go
rec, err := spf.Parse("v=spf1 mx include:_spf.example.com -all")
```
