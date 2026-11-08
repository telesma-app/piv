package card

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"testing/synctest"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

func TestGetCertificateDataReadsFreshMSCUID(t *testing.T) {
	command := []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 0x0d, 0}
	d, _ := newDevice(t,
		exchangeStep{command: command, response: iso7816.Response{
			Status: 0x9000, Data: readTLV(0x53, []byte{0x70, 2, 0x30, 0, 0x71, 1, 0, 0x72, 1, '1', 0xfe, 0}),
		}},
		exchangeStep{command: command, response: iso7816.Response{
			Status: 0x9000, Data: readTLV(0x53, []byte{0x70, 2, 0x30, 0, 0x71, 1, 0, 0x72, 1, '2', 0xfe, 0}),
		}},
	)

	for _, want := range []byte{'1', '2'} {
		got, err := d.GetCertificateData(t.Context(), protocol.RetiredKey1)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(got.DER, []byte{0x30, 0}) || !bytes.Equal(got.MSCUID, []byte{want}) {
			t.Errorf("certificate data = %+v, want DER 3000 and MSCUID %02x", got, want)
		}
	}
}

func TestGetCertificateDataPreservesErrors(t *testing.T) {
	cause := errors.New("card disconnected")
	for _, tc := range []struct {
		name     string
		response iso7816.Response
		err      error
		want     error
		status   iso7816.StatusWord
	}{
		{name: "absent", response: iso7816.Response{Status: 0x6a82}, status: 0x6a82},
		{name: "access denied", response: iso7816.Response{Status: 0x6982}, status: 0x6982},
		{name: "malformed contents", response: iso7816.Response{Status: 0x9000, Data: []byte{0x53, 2, 0xfe, 0}}, want: protocol.ErrInvalidResponse},
		{name: "transport", err: cause, want: cause},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, raw := newDevice(t, exchangeStep{
				command:  []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 0x0d, 0},
				response: tc.response, err: tc.err,
			})

			_, err := d.GetCertificateData(t.Context(), protocol.RetiredKey1)
			if tc.status != 0 {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != tc.status {
					t.Fatalf("GetCertificateData = %v, want APDU %04x", err, uint16(tc.status))
				}
			} else if !errors.Is(err, tc.want) {
				t.Fatalf("GetCertificateData = %v, want %v", err, tc.want)
			}

			if raw.closeCalls != 0 {
				t.Errorf("read error closed the session: %d closes", raw.closeCalls)
			}
		})
	}
}

func TestGetCertificateDataInvalidationClosesSession(t *testing.T) {
	cause := errors.New("card disconnected")
	closeError := errors.New("close failed")
	d, raw := newDevice(t, exchangeStep{
		command: []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 0x0d, 0},
		err:     &transport.DeviceInvalidatedError{Err: cause},
	})
	raw.closeErr = closeError

	_, err := d.GetCertificateData(t.Context(), protocol.RetiredKey1)
	if !errors.Is(err, cause) || !errors.Is(err, closeError) {
		t.Fatalf("invalidation error = %v, want I/O and close errors", err)
	}

	var invalidated *transport.DeviceInvalidatedError
	if !errors.As(err, &invalidated) {
		t.Errorf("lost invalidation type: %v", err)
	}

	if _, err := d.GetCertificateData(t.Context(), protocol.RetiredKey1); !errors.Is(err, io.ErrClosedPipe) || raw.closeCalls != 1 {
		t.Errorf("after invalidation: error=%v, close calls=%d", err, raw.closeCalls)
	}
}

func TestGetCertificateDataRespectsSession(t *testing.T) {
	t.Run("canceled while waiting", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			d, raw := newDevice(t)
			if err := d.lock(t.Context()); err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			result := make(chan error, 1)
			done := make(chan struct{})

			go func() {
				defer close(done)

				_, err := d.GetCertificateData(ctx, protocol.RetiredKey1)
				result <- err
			}()

			defer func() {
				cancel()
				d.unlock()
				receive(t, done, "certificate read worker did not stop after cancellation and gate release")
			}()

			synctest.Wait()

			select {
			case err := <-result:
				t.Fatalf("certificate read completed while the workflow gate was held: %v", err)
			default:
			}

			cancel()

			if err := receive(t, result, "queued certificate read ignored cancellation"); !errors.Is(err, context.Canceled) || raw.calls != 0 || raw.closeCalls != 0 {
				t.Errorf("canceled read = %v, calls=%d, closes=%d", err, raw.calls, raw.closeCalls)
			}
		})
	})
	t.Run("closed", func(t *testing.T) {
		d, raw := newDevice(t)
		if err := d.Close(); err != nil {
			t.Fatal(err)
		}

		if _, err := d.GetCertificateData(t.Context(), protocol.RetiredKey1); !errors.Is(err, io.ErrClosedPipe) || raw.calls != 0 || raw.closeCalls != 1 {
			t.Errorf("closed read = %v, calls=%d, closes=%d", err, raw.calls, raw.closeCalls)
		}
	})
}
