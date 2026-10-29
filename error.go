package spf

import (
	"errors"
)

// Errors behind a ResultPermError, for use with errors.Is on Outcome.Problem.
// A ResultTempError caused by Checker.Timeout or a done context matches
// context.DeadlineExceeded or context.Canceled.
// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4
var (
	// ErrTooManyLookups means more than the lookup limit of terms causing DNS lookups.
	ErrTooManyLookups = errors.New("spf: too many DNS lookups")
	// ErrTooManyVoidLookups means more than two DNS lookups returned no records.
	ErrTooManyVoidLookups = errors.New("spf: too many void DNS lookups")
	// ErrTooManyMX means a "mx" mechanism found more than 10 MX records.
	ErrTooManyMX = errors.New("spf: too many MX records")
	// ErrMultipleRecords means a domain published more than one SPF record.
	// ref: https://datatracker.ietf.org/doc/html/rfc7208#section-4.5
	ErrMultipleRecords = errors.New("spf: multiple SPF records")
	// ErrNoRecord means the domain of an "include" or "redirect" has no SPF record.
	// A checked identity without a record gives ResultNone instead.
	ErrNoRecord = errors.New("spf: no SPF record")
)

// checkError carries the result that a failure during the check leads to.
// If it's returned while processing a mechanism, processing ends and the
// result is returned.
type checkError struct {
	result  Result
	message string
	err     error
}

func newCheckError(result Result, message string) *checkError {
	return &checkError{result: result, message: message}
}

func wrapCheckError(err error, result Result, message string) *checkError {
	return &checkError{result: result, message: message, err: err}
}

func (e *checkError) Error() string {
	switch {
	case e.err == nil:
		return e.message
	case e.message == "":
		return e.err.Error()
	default:
		return e.message + ": " + e.err.Error()
	}
}

func (e *checkError) Unwrap() error {
	return e.err
}
