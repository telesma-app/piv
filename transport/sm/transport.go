package sm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

// Parameters supplies explicit card trust, cipher suite and protected APDU encoding.
// HostID is a locally assigned client identifier; zero is permitted by NIST.
// CipherSuite must be protocol.CipherSuite2 or protocol.CipherSuite7.
// Encoding must be EncodingShort (with chaining) or EncodingExtended. Handshake
// commands use short encoding. No suite or encoding fallback is performed.
type Parameters struct {
	Trust       Trust
	CipherSuite protocol.Algorithm
	HostID      [8]byte
	Encoding    iso7816.Encoding
}

// Transport owns a CS2 or CS7 session and its connection. Create it with Open
// and stop using the underlying connection independently. A Transport must not be copied.
type Transport struct {
	connection  transport.Device
	application protocol.ApplicationPropertyTemplate
	session     recordSession
	mu          chan struct{}
	cryptoMu    sync.Mutex
	closed      chan struct{}
	closeOnce   sync.Once
	closeErr    error
}

var _ transport.Device = (*Transport)(nil)

// Open reselects PIV, requires support for the requested suite, and authenticates
// a fresh session against parameters.Trust. The caller serializes initialization with
// all other connection users. Ownership transfers only on success. On failure
// the caller retains ownership; a DeviceInvalidatedError additionally means the
// connection has been closed and must not be reused.
func Open(ctx context.Context, connection transport.Device, parameters Parameters) (*Transport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if parameters.Encoding != iso7816.EncodingShort && parameters.Encoding != iso7816.EncodingExtended {
		return nil, fmt.Errorf("sm: select short or extended APDU encoding explicitly")
	}

	suite, err := selectCipherSuite(parameters.CipherSuite)
	if err != nil {
		return nil, err
	}

	keys, application, err := establish(ctx, connection, parameters, suite)
	if err != nil {
		var invalidated *transport.DeviceInvalidatedError
		if errors.As(err, &invalidated) {
			return nil, errors.Join(err, connection.Close())
		}

		return nil, err
	}
	defer keys.clear()

	return &Transport{
		connection:  connection,
		application: application,
		session:     newRecordSession(keys, parameters.Encoding),
		mu:          make(chan struct{}, 1),
		closed:      make(chan struct{}),
	}, nil
}

// ApplicationProperties returns the SELECT result used to establish this
// channel without I/O. Its slices are read-only and remain available after Close.
// The snapshot describes advertised algorithms, not current authentication state.
func (t *Transport) ApplicationProperties() protocol.ApplicationPropertyTemplate {
	return t.application
}

func invalidHandshake(err error) error {
	return &transport.DeviceInvalidatedError{Err: err}
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

// Close prevents new exchanges, erases owned session keys and closes the
// connection once. It does not wait for the exchange gate or hold the crypto
// mutex during I/O. Repeated calls return the same close error.
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
