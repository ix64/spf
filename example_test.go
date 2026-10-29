package spf_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/ix64/spf"
)

func ExampleCheckMailFrom() {
	ctx := context.Background()
	clientIP := netip.MustParseAddr("192.0.2.1")

	o := spf.CheckMailFrom(ctx, clientIP, "user@example.com", "mail.example.com")
	switch o.Result {
	case spf.ResultFail:
		fmt.Println("reject:", o.Explanation)
	case spf.ResultTempError:
		fmt.Println("try again later:", o.Problem)
	}
	fmt.Println("Received-SPF: " + o.ReceivedSPF())
}

func ExampleChecker() {
	// create the Checker once and share it between connections
	checker := &spf.Checker{
		Resolver: &net.Resolver{PreferGo: true},
		Receiver: "mx.example.net",
		Timeout:  10 * time.Second,
		Logger:   slog.Default(),
	}

	ctx := context.Background()
	clientIP := netip.MustParseAddr("192.0.2.1")

	// a "pass" for HELO makes checking MAIL FROM unnecessary
	o := checker.CheckHelo(ctx, clientIP, "mail.example.com")
	if o.Result != spf.ResultPass {
		o = checker.CheckMailFrom(ctx, clientIP, "user@example.com", "mail.example.com")
	}
	if errors.Is(o.Problem, spf.ErrTooManyLookups) {
		fmt.Println("the SPF record of the domain needs too many DNS lookups")
	}
	fmt.Println(o.Result)
}

func ExampleParse() {
	rec, err := spf.Parse("v=spf1 mx include:_spf.example.com ip4:192.0.2.0/24 -all")
	if err != nil {
		log.Fatal(err)
	}
	for _, d := range rec.Directives {
		fmt.Printf("%c %s\n", d.Qualifier, d.Mechanism)
	}

	_, err = spf.Parse("v=spf1 a:example.com -al")
	fmt.Println(err)
	// Output:
	// + mx
	// + include:_spf.example.com
	// + ip4:192.0.2.0/24
	// - all
	// spf: invalid term "-al": unknown mechanism "al"
}

func ExampleOutcome_ReceivedSPF() {
	o := spf.Outcome{
		Result:    spf.ResultPass,
		Identity:  spf.IdentityMailFrom,
		Sender:    "user@example.com",
		MailFrom:  "user@example.com",
		ClientIP:  netip.MustParseAddr("192.0.2.1"),
		Helo:      "mail.example.com",
		Receiver:  "mx.example.net",
		Mechanism: "ip4:192.0.2.0/24",
	}
	fmt.Println("Received-SPF: " + o.ReceivedSPF())
	// Output:
	// Received-SPF: pass (mx.example.net: domain of user@example.com designates 192.0.2.1 as permitted sender) receiver=mx.example.net; client-ip=192.0.2.1; envelope-from="user@example.com"; helo=mail.example.com; identity=mailfrom; mechanism="ip4:192.0.2.0/24";
}
