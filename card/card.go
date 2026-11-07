package card

import (
	"context"
	"errors"
	"io"
	"slices"
	"sync"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/client"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

// Device owns a selected PIV connection and serializes complete card operations.
// Create it with New. A Device must not be copied.
type Device struct {
	transport      transport.Device
	client         *client.Client
	application    protocol.ApplicationPropertyTemplate
	hasApplication bool
	mu             chan struct{}
	closed         chan struct{}
	closeOnce      sync.Once
	closeErr       error
}

type applicationProperties interface {
	ApplicationProperties() protocol.ApplicationPropertyTemplate
}

var _ transport.Device = (*Device)(nil)

// New takes ownership of an initialized transport without performing I/O.
// PIV must already be selected, as by backend/pcsc.Open or
// transport/iso7816.Open. The caller must stop using the transport directly.
// An initial SELECT snapshot is retained when the transport provides
// ApplicationProperties, as the ISO 7816 and NIST secure-messaging transports do.
func New(transport transport.Device) *Device {
	device := &Device{
		transport: transport,
		client:    client.NewClient(transport),
		mu:        make(chan struct{}, 1),
		closed:    make(chan struct{}),
	}
	if source, ok := transport.(applicationProperties); ok {
		device.application = source.ApplicationProperties()
		device.hasApplication = true
	}

	return device
}

// NewWithApplicationProperties takes ownership as New does and retains an
// explicit snapshot of an earlier SELECT result. Use it when a transport wrapper
// such as SCP11 does not expose that result. The caller binds the properties to
// the correct connection. Slices are copied so the caller may reuse its input.
func NewWithApplicationProperties(transport transport.Device, application protocol.ApplicationPropertyTemplate) *Device {
	device := New(transport)
	application.AID = slices.Clone(application.AID)
	application.TagAllocationAuthorityAID = slices.Clone(application.TagAllocationAuthorityAID)
	application.Algorithms = slices.Clone(application.Algorithms)
	device.application = application
	device.hasApplication = true

	return device
}

// ApplicationProperties returns the initial SELECT snapshot without I/O. False
// means that the transport did not provide one and none was supplied explicitly.
// The returned slices are read-only. The snapshot remains available after Close
// and does not describe current authentication or key state.
func (d *Device) ApplicationProperties() (protocol.ApplicationPropertyTemplate, bool) {
	return d.application, d.hasApplication
}

// lock reserves the connection for a complete workflow. Its client commands
// use the underlying transport directly to avoid re-entering this gate.
func (d *Device) lock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-d.closed:
		return io.ErrClosedPipe
	case d.mu <- struct{}{}:
	}

	if err := ctx.Err(); err != nil {
		d.unlock()
		return err
	}

	select {
	case <-d.closed:
		d.unlock()
		return io.ErrClosedPipe
	default:
	}

	return nil
}

func (d *Device) unlock() {
	<-d.mu
}

// operationError closes an invalidated session before releasing its workflow
// gate, so a queued operation cannot reuse the connection.
func (d *Device) operationError(err error) error {
	if _, ok := errors.AsType[*transport.DeviceInvalidatedError](err); ok {
		return errors.Join(err, d.Close())
	}

	return err
}

// Exchange sends one complete APDU command through the same gate as card
// workflows. It is the access boundary for vendor commands. Like transport.APDU,
// it returns the final status word without interpretation. Separate Exchange
// calls do not form an atomic multi-command workflow. Commands must leave PIV
// selected for subsequent card operations.
func (d *Device) Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	if err := d.lock(ctx); err != nil {
		return iso7816.Response{}, err
	}
	defer d.unlock()

	response, err := d.transport.Exchange(ctx, command)

	return response, d.operationError(err)
}

// Close prevents new operations and closes the transport once. Waiting callers
// return io.ErrClosedPipe even while the underlying Close is still running.
// Close does not acquire the workflow gate; interrupting active I/O and waiting
// for its completion follow the transport's contract. Repeated calls return
// the same close error.
func (d *Device) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
		d.closeErr = d.transport.Close()
	})

	return d.closeErr
}
