package iso7816

import (
	"context"
	"errors"
	"io"
	"sync"

	baseiso7816 "github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	pivtransport "github.com/telesma-app/piv/transport"
)

// Card is a closable APDU connection. Close must be safe during Transmit and
// should interrupt it when the underlying implementation supports cancellation.
type Card interface {
	baseiso7816.Card
	io.Closer
}

// Transport owns a selected PIV card and serializes complete APDU exchanges.
type Transport struct {
	card        Card
	application protocol.ApplicationPropertyTemplate
	mu          chan struct{}
	closed      chan struct{}
	closeOnce   sync.Once
	closeErr    error
}

var _ pivtransport.Device = (*Transport)(nil)

// Open selects PIV and takes ownership of card on success. On failure, the
// caller retains ownership, including when the connection was invalidated.
// ApplicationProperties retains the result of this SELECT without further I/O.
func Open(ctx context.Context, card Card) (*Transport, error) {
	application, err := Select(ctx, card)
	if err != nil {
		return nil, err
	}

	return &Transport{
		card:        card,
		application: application,
		mu:          make(chan struct{}, 1),
		closed:      make(chan struct{}),
	}, nil
}

// ApplicationProperties returns the initial SELECT result without I/O. Its
// slices are read-only views that remain available after Close.
func (t *Transport) ApplicationProperties() protocol.ApplicationPropertyTemplate {
	return t.application
}

// Exchange sends one complete PIV command. An invalidated card is closed before
// the error is returned. Waiting for another exchange respects ctx; Close
// releases waiting callers with io.ErrClosedPipe without transmitting an APDU.
func (t *Transport) Exchange(ctx context.Context, command baseiso7816.Command) (baseiso7816.Response, error) {
	select {
	case <-ctx.Done():
		return baseiso7816.Response{}, ctx.Err()
	case <-t.closed:
		return baseiso7816.Response{}, io.ErrClosedPipe
	case t.mu <- struct{}{}:
	}

	defer func() { <-t.mu }()

	select {
	case <-t.closed:
		return baseiso7816.Response{}, io.ErrClosedPipe
	default:
	}

	response, err := Exchange(ctx, t.card, command)

	var invalidated *pivtransport.DeviceInvalidatedError
	if errors.As(err, &invalidated) {
		err = errors.Join(err, t.Close())
	}

	return response, err
}

// Close prevents further exchanges and closes the card once. It can run during
// Exchange without waiting for it; completion depends on the card's
// cancellation support.
func (t *Transport) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)

		if err := t.card.Close(); err != nil {
			t.closeErr = &pivtransport.IOError{Operation: pivtransport.IOClose, Err: err}
		}
	})

	return t.closeErr
}
