package card

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

func TestNewOwnsTransportWithoutIO(t *testing.T) {
	d, raw := newDevice(t)
	if raw.calls != 0 || raw.closeCalls != 0 {
		t.Fatalf("New performed I/O: exchanges=%d closes=%d", raw.calls, raw.closeCalls)
	}

	closeErr := errors.New("disconnect failed")
	raw.closeErr = closeErr

	for range 2 {
		if err := d.Close(); !errors.Is(err, closeErr) {
			t.Errorf("Close = %v, want %v", err, closeErr)
		}
	}

	if raw.closeCalls != 1 {
		t.Errorf("close count = %d, want 1", raw.closeCalls)
	}

	if _, err := d.Exchange(t.Context(), iso7816.Command{INS: 0xfd}); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("Exchange after Close = %v, want ErrClosedPipe", err)
	}

	if _, err := d.GetData(t.Context(), protocol.CardCapabilityContainer); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("GetData after Close = %v, want ErrClosedPipe", err)
	}
}

func TestExchangeReturnsFinalStatus(t *testing.T) {
	d, _ := newDevice(t, exchangeStep{
		command:  []byte{0, 0xfd, 1, 2, 2, 3, 4, 0},
		response: iso7816.Response{Status: 0x6982, Data: []byte{5, 6}},
	})

	response, err := d.Exchange(t.Context(), iso7816.Command{
		INS: 0xfd, P1: 1, P2: 2, Data: []byte{3, 4}, Le: 256,
	})
	if err != nil {
		t.Fatal(err)
	}

	if response.Status != 0x6982 || !bytes.Equal(response.Data, []byte{5, 6}) {
		t.Errorf("response = %+v, want status 6982 and data 0506", response)
	}
}

func TestOperationErrorPreservesSession(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response iso7816.Response
	}{
		{name: "absent object", response: iso7816.Response{Status: 0x6a82}},
		{name: "malformed object", response: iso7816.Response{Status: 0x9000, Data: []byte{0x53, 1}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 7, 0}
			d, raw := newDevice(t,
				exchangeStep{command: command, response: tc.response},
				exchangeStep{command: command, response: iso7816.Response{Status: 0x9000, Data: []byte{0x53, 1, 1}}},
			)

			_, err := d.GetData(t.Context(), protocol.CardCapabilityContainer)
			if tc.response.Status == 0x6a82 {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != 0x6a82 {
					t.Fatalf("GetData = %v, want APDU error 6A82", err)
				}
			} else if !errors.Is(err, protocol.ErrInvalidResponse) {
				t.Fatalf("GetData = %v, want ErrInvalidResponse", err)
			}

			if raw.closeCalls != 0 {
				t.Fatal("ordinary operation error closed the session")
			}

			data, err := d.GetData(t.Context(), protocol.CardCapabilityContainer)
			if err != nil || !bytes.Equal(data, []byte{1}) {
				t.Fatalf("GetData after error = %x, %v; want 01", data, err)
			}
		})
	}
}

func TestInvalidationClosesSessionAndPreservesErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command []byte
		run     func(context.Context, *Device) error
	}{
		{
			name: "raw exchange", command: []byte{0, 0xfd, 0, 0},
			run: func(ctx context.Context, d *Device) error {
				_, err := d.Exchange(ctx, iso7816.Command{INS: 0xfd})
				return err
			},
		},
		{
			name: "object", command: []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 7, 0},
			run: func(ctx context.Context, d *Device) error {
				_, err := d.GetData(ctx, protocol.CardCapabilityContainer)
				return err
			},
		},
		{
			name: "certificate", command: []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 5, 0},
			run: func(ctx context.Context, d *Device) error {
				_, err := d.GetCertificate(ctx, protocol.PIVAuthentication)
				return err
			},
		},
		{
			name: "PIN status", command: []byte{0, 0x20, 0, 0x80},
			run: func(ctx context.Context, d *Device) error {
				_, err := d.ReferenceStatus(ctx, protocol.ApplicationPIN)
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cause := errors.New("card removed")
			closeErr := errors.New("disconnect failed")
			d, raw := newDevice(t, exchangeStep{command: tc.command, err: &transport.DeviceInvalidatedError{Err: cause}})
			raw.closeErr = closeErr

			err := tc.run(t.Context(), d)

			var invalidated *transport.DeviceInvalidatedError
			if !errors.As(err, &invalidated) || !errors.Is(err, cause) || !errors.Is(err, closeErr) {
				t.Fatalf("operation = %v, want invalidation and both causes", err)
			}

			if raw.closeCalls != 1 {
				t.Errorf("close count = %d, want 1", raw.closeCalls)
			}

			if err := tc.run(t.Context(), d); !errors.Is(err, io.ErrClosedPipe) {
				t.Errorf("operation after invalidation = %v, want ErrClosedPipe", err)
			}

			if err := d.Close(); !errors.Is(err, closeErr) || raw.closeCalls != 1 {
				t.Errorf("Close after invalidation = %v, close count %d", err, raw.closeCalls)
			}
		})
	}
}

func TestCanceledOperationDoesNotStartIO(t *testing.T) {
	d, raw := newDevice(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := d.Exchange(ctx, iso7816.Command{INS: 0xfd})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Exchange = %v, want context cancellation", err)
	}

	if raw.closeCalls != 0 {
		t.Fatal("pre-cancellation closed the session")
	}
}

func readWorkflow(ctx context.Context, d *Device, objects ...protocol.Object) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()

	for _, object := range objects {
		if _, err := d.client.GetData(ctx, object); err != nil {
			return d.operationError(err)
		}
	}

	return nil
}

func TestWorkflowsAndVendorExchangeShareGate(t *testing.T) {
	for _, tc := range []struct {
		name  string
		steps []exchangeStep
		run   func(context.Context, *Device) error
	}{
		{
			name: "second workflow",
			steps: []exchangeStep{
				{command: []byte{0, 0xcb, 0x3f, 0xff, 3, 0x5c, 1, 0x7e, 0}, response: iso7816.Response{Status: 0x9000, Data: []byte{0x7e, 0}}},
				{command: []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 0x0c, 0}, response: iso7816.Response{Status: 0x9000, Data: []byte{0x53, 0}}},
			},
			run: func(ctx context.Context, d *Device) error {
				return readWorkflow(ctx, d, protocol.DiscoveryObject, protocol.KeyHistoryObject)
			},
		},
		{
			name:  "vendor exchange",
			steps: []exchangeStep{{command: []byte{0, 0xfd, 0, 0}, response: iso7816.Response{Status: 0x9000}}},
			run: func(ctx context.Context, d *Device) error {
				_, err := d.Exchange(ctx, iso7816.Command{INS: 0xfd})
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				started := make(chan struct{})
				proceed := make(chan struct{})

				release := sync.OnceFunc(func() { close(proceed) })
				defer release()

				steps := []exchangeStep{
					{
						command:  []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 7, 0},
						response: iso7816.Response{Status: 0x9000, Data: []byte{0x53, 0}},
						after:    func() { close(started); <-proceed },
					},
					{command: []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 2, 0}, response: iso7816.Response{Status: 0x9000, Data: []byte{0x53, 0}}},
				}
				steps = append(steps, tc.steps...)
				d, raw := newDevice(t, steps...)

				first := make(chan error, 1)
				go func() {
					first <- readWorkflow(t.Context(), d, protocol.CardCapabilityContainer, protocol.CardholderUniqueIdentifier)
				}()

				receive(t, started, "first workflow did not start")

				second := make(chan error, 1)
				go func() { second <- tc.run(t.Context(), d) }()

				synctest.Wait()

				if raw.calls != 1 {
					t.Fatalf("exchange count while first workflow is active = %d, want 1", raw.calls)
				}

				release()

				if err := receive(t, first, "first workflow did not finish"); err != nil {
					t.Fatal(err)
				}

				if err := receive(t, second, "second operation did not finish"); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestQueuedContextPreservesActiveSession(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "cancellation"
		if deadline {
			name = "deadline"
		}

		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				started := make(chan struct{})
				proceed := make(chan struct{})

				release := sync.OnceFunc(func() { close(proceed) })
				defer release()

				d, raw := newDevice(t,
					exchangeStep{
						command:  []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 7, 0},
						response: iso7816.Response{Status: 0x9000, Data: []byte{0x53, 0}},
						after:    func() { close(started); <-proceed },
					},
					exchangeStep{command: []byte{0, 0xfd, 0, 0}, response: iso7816.Response{Status: 0x9000}},
				)
				first := make(chan error, 1)

				go func() { _, err := d.GetData(t.Context(), protocol.CardCapabilityContainer); first <- err }()

				receive(t, started, "active read did not start")

				ctx, cancel := context.WithTimeout(t.Context(), time.Hour)
				if deadline {
					cancel()
					ctx, cancel = context.WithTimeout(t.Context(), time.Second)
				}
				defer cancel()

				queued := make(chan error, 1)

				go func() { _, err := d.Exchange(ctx, iso7816.Command{INS: 0xfd}); queued <- err }()

				synctest.Wait()

				if deadline {
					time.Sleep(time.Second)
				} else {
					cancel()
				}

				if err := receive(t, queued, "queued operation ignored context"); !errors.Is(err, ctx.Err()) {
					t.Fatalf("queued operation = %v, want %v", err, ctx.Err())
				}

				if raw.calls != 1 || raw.closeCalls != 0 {
					t.Fatalf("queued context changed session: exchanges=%d closes=%d", raw.calls, raw.closeCalls)
				}

				release()

				if err := receive(t, first, "active read did not finish"); err != nil {
					t.Fatal(err)
				}

				response, err := d.Exchange(t.Context(), iso7816.Command{INS: 0xfd})
				if err != nil || response.Status != 0x9000 {
					t.Fatalf("Exchange after queued context = %s, %v", response.Status, err)
				}
			})
		})
	}
}

type slowCloseTransport struct {
	started     chan struct{}
	closing     chan struct{}
	releaseIO   chan struct{}
	finishClose chan struct{}
	closeCalls  int
}

func (s *slowCloseTransport) Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	close(s.started)
	<-s.releaseIO

	return iso7816.Response{}, io.ErrClosedPipe
}

func (s *slowCloseTransport) Close() error {
	s.closeCalls++
	close(s.closing)
	<-s.finishClose

	return nil
}

func TestCloseReleasesQueueWhileTransportIsClosing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		raw := &slowCloseTransport{
			started: make(chan struct{}), closing: make(chan struct{}),
			releaseIO: make(chan struct{}), finishClose: make(chan struct{}),
		}

		releaseIO := sync.OnceFunc(func() { close(raw.releaseIO) })
		finishClose := sync.OnceFunc(func() { close(raw.finishClose) })
		d := New(raw)
		ctx, cancel := context.WithCancel(t.Context())

		var workers sync.WaitGroup

		defer func() {
			cancel()
			releaseIO()
			finishClose()

			_ = d.Close()

			done := make(chan struct{})

			go func() { workers.Wait(); close(done) }()

			receive(t, done, "workers did not stop after cleanup")
		}()

		active := make(chan error, 1)

		workers.Go(func() { _, err := d.Exchange(ctx, iso7816.Command{INS: 0xfd}); active <- err })

		receive(t, raw.started, "active operation did not start")

		queued := make(chan error, 1)

		workers.Go(func() { _, err := d.GetData(ctx, protocol.CardCapabilityContainer); queued <- err })

		synctest.Wait()

		select {
		case err := <-queued:
			t.Fatalf("queued operation completed before Close: %v", err)
		default:
		}

		closed := make(chan error, 1)

		workers.Go(func() { closed <- d.Close() })

		receive(t, raw.closing, "Close waited for the workflow gate")

		if err := receive(t, queued, "queued operation waited for transport Close"); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("queued operation = %v, want ErrClosedPipe", err)
		}

		select {
		case err := <-active:
			t.Fatalf("active operation completed before I/O release: %v", err)
		default:
		}

		select {
		case err := <-closed:
			t.Fatalf("Close returned before transport finished: %v", err)
		default:
		}

		releaseIO()

		if err := receive(t, active, "active operation did not stop after I/O release"); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("active operation = %v, want I/O failure", err)
		}

		finishClose()

		if err := receive(t, closed, "Close did not finish"); err != nil {
			t.Fatal(err)
		}

		if raw.closeCalls != 1 {
			t.Errorf("close count = %d, want 1", raw.closeCalls)
		}
	})
}

func TestCompletedResponsePreservedAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	d, raw := newDevice(t, exchangeStep{
		command: []byte{0, 0x20, 0, 0x80}, response: iso7816.Response{Status: 0x63c3}, after: cancel,
	})

	status, err := d.ReferenceStatus(ctx, protocol.ApplicationPIN)
	if err != nil || status.Verified || status.Retries != 3 {
		t.Fatalf("ReferenceStatus = %+v, %v; want completed three-retry response", status, err)
	}

	if raw.closeCalls != 0 {
		t.Fatal("completed response invalidated the session")
	}
}
