package sm

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

// Transport owns a CS2 or CS7 session and its connection. Create it with Open
// and stop using the underlying connection independently. A Transport must not be copied.
type Transport struct {
	connection  transport.Device
	application protocol.ApplicationPropertyTemplate
	certificate CardCertificate
	session     recordSession
	mu          chan struct{}
	cryptoMu    sync.Mutex
	closed      chan struct{}
	closeOnce   sync.Once
	closeErr    error
}

var _ transport.Device = (*Transport)(nil)

// ApplicationProperties returns the SELECT result used to establish this
// channel without I/O. Its slices are read-only and remain available after Close.
func (t *Transport) ApplicationProperties() protocol.ApplicationPropertyTemplate {
	return t.application
}

// CardCertificate returns the card identity authenticated by Open without I/O.
// Its Raw bytes are read-only. The snapshot is independent of the connection's
// response buffers and remains available after Close.
func (t *Transport) CardCertificate() CardCertificate {
	return t.certificate
}

// PIVSecureMessaging reports whether this NIST secure messaging transport is
// open. It supports the card layer's explicit virtual contact interface workflow.
func (t *Transport) PIVSecureMessaging() bool {
	select {
	case <-t.closed:
		return false
	default:
		return true
	}
}

// Exchange protects one complete PIV command before underlying fragmentation
// and authenticates the assembled response before exposing plaintext or status.
// Only GET DATA, VERIFY, CHANGE REFERENCE DATA and GENERAL AUTHENTICATE are
// supported (§4.2). Authenticated application errors preserve the session.
// Framing GET RESPONSE is the underlying transport's responsibility (CLA 00).
func (t *Transport) Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	if err := t.lock(ctx); err != nil {
		return iso7816.Response{}, err
	}
	defer func() { <-t.mu }()

	t.cryptoMu.Lock()
	if !t.PIVSecureMessaging() {
		t.cryptoMu.Unlock()
		return iso7816.Response{}, io.ErrClosedPipe
	}

	protected, next, err := t.session.protect(command)
	t.cryptoMu.Unlock()

	if err != nil {
		if errors.Is(err, ErrSessionExhausted) {
			return iso7816.Response{}, t.invalidate(err)
		}

		return iso7816.Response{}, err
	}

	if err := ctx.Err(); err != nil {
		return iso7816.Response{}, err
	}

	response, err := t.connection.Exchange(ctx, protected)
	if err != nil {
		var invalidated *transport.DeviceInvalidatedError
		if !errors.As(err, &invalidated) && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			// The complete-exchange contract distinguishes cancellation before
			// I/O from an interrupted exchange. protect has not committed state.
			return iso7816.Response{}, err
		}

		return iso7816.Response{}, t.invalidate(err)
	}

	t.cryptoMu.Lock()
	if !t.PIVSecureMessaging() {
		t.cryptoMu.Unlock()
		return iso7816.Response{}, io.ErrClosedPipe
	}

	plaintext, err := t.session.unprotect(response, next)
	t.cryptoMu.Unlock()

	if err != nil {
		return iso7816.Response{}, t.invalidate(err)
	}

	return plaintext, nil
}

func (t *Transport) lock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.closed:
		return io.ErrClosedPipe
	case t.mu <- struct{}{}:
	}

	if err := ctx.Err(); err != nil {
		<-t.mu
		return err
	}

	if !t.PIVSecureMessaging() {
		<-t.mu
		return io.ErrClosedPipe
	}

	return nil
}

func (t *Transport) invalidate(err error) error {
	if _, ok := errors.AsType[*transport.DeviceInvalidatedError](err); !ok {
		err = &transport.DeviceInvalidatedError{Err: err}
	}

	return errors.Join(err, t.Close())
}

// Close prevents new exchanges, erases session keys, and closes the connection
// once. It can run concurrently with Exchange. Repeated calls return the same error.
func (t *Transport) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		t.cryptoMu.Lock()
		t.session.clear()
		t.cryptoMu.Unlock()
		t.closeErr = t.connection.Close()
	})

	return t.closeErr
}
