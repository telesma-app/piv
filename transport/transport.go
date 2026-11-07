// Package transport defines the PIV APDU exchange boundary.
package transport

import (
	"context"
	"io"

	"github.com/telesma-app/iso7816"
)

// APDU exchanges a complete PIV command, including command chaining and GET
// RESPONSE. Intermediate fragments require a successful acknowledgement;
// their rejection returns an iso7816.APDUError. The final status word is
// returned without interpretation. Cancellation before I/O preserves the
// connection; interruption after I/O must return DeviceInvalidatedError so
// session transports can distinguish it from a command that was never sent.
type APDU interface {
	Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error)
}

// Device is an owned PIV connection. Close must be safe alongside Exchange.
type Device interface {
	APDU
	io.Closer
}

// IOOperation identifies the failed underlying card operation.
type IOOperation string

const (
	IOTransmit IOOperation = "transmit"
	IOClose    IOOperation = "close"
)

// IOError identifies a card I/O failure and preserves its cause.
type IOError struct {
	Operation IOOperation
	Err       error
}

func (e *IOError) Error() string {
	return "transport " + string(e.Operation) + ": " + e.Err.Error()
}

func (e *IOError) Unwrap() error {
	return e.Err
}

// DeviceInvalidatedError marks a connection that must not be reused. Owned
// transports close the card before returning; borrowed card users must close it.
type DeviceInvalidatedError = iso7816.DeviceInvalidatedError
