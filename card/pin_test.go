package card

import (
	"errors"
	"io"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/client"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

func TestPINMaintenanceUsesOwnedSession(t *testing.T) {
	d, raw := newDevice(t,
		exchangeStep{
			command:  []byte{0, 0x20, 0, 0x80, 8, '1', '2', '3', '4', '5', '6', 0xff, 0xff},
			response: iso7816.Response{Status: 0x63c2},
		},
		exchangeStep{
			command: []byte{0, 0x24, 0, 0x80, 16,
				'1', '2', '3', '4', '5', '6', 0xff, 0xff, '8', '7', '6', '5', '4', '3', 0xff, 0xff},
			response: iso7816.Response{Status: 0x9000},
		},
		exchangeStep{
			command: []byte{0, 0x20, 0xff, 0x80}, response: iso7816.Response{Status: 0x9000},
		},
		exchangeStep{
			command: []byte{0, 0x2c, 0, 0x80, 16,
				1, 2, 3, 4, 5, 6, 7, 8, '1', '2', '3', '4', '5', '6', '7', '8'},
			response: iso7816.Response{Status: 0x9000},
		},
	)

	err := d.VerifyPIN(t.Context(), "123456")

	var referenceError *client.ReferenceDataError
	if !errors.As(err, &referenceError) || referenceError.Retries != 2 {
		t.Fatalf("VerifyPIN = %v, want two retries", err)
	}

	if err := d.ChangePIN(t.Context(), "123456", "876543"); err != nil {
		t.Fatal(err)
	}

	if err := d.ResetSecurityStatus(t.Context(), protocol.ApplicationPIN); err != nil {
		t.Fatal(err)
	}

	if err := d.UnblockPIN(t.Context(), [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, "12345678"); err != nil {
		t.Fatal(err)
	}

	if raw.closeCalls != 0 {
		t.Fatal("PIN retry status closed the owned session")
	}
}

func TestEncodedPINMaintenancePreservesCallerValues(t *testing.T) {
	current := [8]byte{1, 2, 3, 4, 5, 6, 0xff, 0xff}
	replacement := [8]byte{6, 5, 4, 3, 2, 1, 0xff, 0xff}
	d, _ := newDevice(t,
		exchangeStep{
			command: []byte{0, 0x24, 0, 0x81, 16,
				1, 2, 3, 4, 5, 6, 0xff, 0xff, 6, 5, 4, 3, 2, 1, 0xff, 0xff},
			response: iso7816.Response{Status: 0x9000},
		},
		exchangeStep{
			command: []byte{0, 0x2c, 0, 0x80, 16,
				6, 5, 4, 3, 2, 1, 0xff, 0xff, 1, 2, 3, 4, 5, 6, 0xff, 0xff},
			response: iso7816.Response{Status: 0x9000},
		},
	)

	if err := d.ChangeReferenceData(t.Context(), protocol.PUK, current, replacement); err != nil {
		t.Fatal(err)
	}

	if err := d.ResetRetryCounter(t.Context(), replacement, current); err != nil {
		t.Fatal(err)
	}

	if current != [8]byte{1, 2, 3, 4, 5, 6, 0xff, 0xff} || replacement != [8]byte{6, 5, 4, 3, 2, 1, 0xff, 0xff} {
		t.Fatal("PIN maintenance changed caller-owned values")
	}
}

func TestVerifyInvalidationClosesOwnedSession(t *testing.T) {
	want := &transport.DeviceInvalidatedError{Err: io.ErrUnexpectedEOF}
	d, raw := newDevice(t, exchangeStep{
		command: []byte{0, 0x20, 0, 0x96, 6, 1, 2, 3, 4, 5, 6}, err: want,
	})

	err := d.Verify(t.Context(), protocol.VerifyRequest{
		Reference: protocol.PrimaryFingerOCC, Data: []byte{1, 2, 3, 4, 5, 6},
	})
	if !errors.Is(err, want) || raw.closeCalls != 1 {
		t.Fatalf("Verify = %v, close count = %d; want invalidation and one close", err, raw.closeCalls)
	}

	if err := d.ChangePIN(t.Context(), "123456", "876543"); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("ChangePIN after invalidation = %v, want ErrClosedPipe", err)
	}
}
