package client

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

func TestReferenceStatus(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status iso7816.StatusWord
		want   ReferenceStatus
	}{
		{"verified", 0x9000, ReferenceStatus{Verified: true}},
		{"three retries", 0x63c3, ReferenceStatus{Retries: 3}},
		{"zero retries", 0x63c0, ReferenceStatus{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient(newScript(t, exchangeStep{
				command: []byte{0, 0x20, 0, 0x80}, response: iso7816.Response{Status: tc.status},
			}))

			got, err := c.ReferenceStatus(t.Context(), protocol.ApplicationPIN)
			if err != nil || got != tc.want {
				t.Fatalf("ReferenceStatus = %+v, %v; want %+v", got, err, tc.want)
			}
		})
	}
}

func TestReferenceStatusPreservesUnknownRetryStatus(t *testing.T) {
	c := NewClient(newScript(t, exchangeStep{
		command: []byte{0, 0x20, 0, 0x80}, response: iso7816.Response{Status: 0x6983},
	}))

	_, err := c.ReferenceStatus(t.Context(), protocol.ApplicationPIN)

	var apduError *iso7816.APDUError
	if !errors.As(err, &apduError) || apduError.StatusWord() != 0x6983 {
		t.Fatalf("ReferenceStatus = %v, want APDU status 6983 without an inferred retry count", err)
	}
}

func TestReferenceStatusRejectsUnexpectedResponseData(t *testing.T) {
	for _, status := range []iso7816.StatusWord{0x9000, 0x63c3} {
		t.Run(status.String(), func(t *testing.T) {
			c := NewClient(newScript(t, exchangeStep{
				command:  []byte{0, 0x20, 0, 0x80},
				response: iso7816.Response{Status: status, Data: []byte{1}},
			}))

			if _, err := c.ReferenceStatus(t.Context(), protocol.ApplicationPIN); !errors.Is(err, protocol.ErrInvalidResponse) {
				t.Fatalf("ReferenceStatus error = %v, want ErrInvalidResponse", err)
			}
		})
	}
}

func TestReferenceStatusPreservesTransportInvalidation(t *testing.T) {
	want := &transport.DeviceInvalidatedError{Err: &ReferenceDataError{
		Reference: protocol.ApplicationPIN, Retries: 3, Status: 0x63c3,
	}}
	c := NewClient(newScript(t, exchangeStep{
		command: []byte{0, 0x20, 0, 0x80}, err: want,
	}))

	_, err := c.ReferenceStatus(t.Context(), protocol.ApplicationPIN)
	if !errors.Is(err, want) {
		t.Fatalf("ReferenceStatus = %v, want original transport invalidation", err)
	}
}

func TestVerifyPIN(t *testing.T) {
	c := NewClient(newScript(t, exchangeStep{
		command:  []byte{0, 0x20, 0, 0x80, 8, '1', '2', '3', '4', '5', '6', 0xff, 0xff},
		response: iso7816.Response{Status: 0x9000},
	}))
	if err := c.VerifyPIN(t.Context(), "123456"); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyPINReturnsReferenceDataError(t *testing.T) {
	c := NewClient(newScript(t, exchangeStep{
		command:  []byte{0, 0x20, 0, 0x80, 8, '1', '2', '3', '4', '5', '6', 0xff, 0xff},
		response: iso7816.Response{Status: 0x63c2},
	}))
	err := c.VerifyPIN(t.Context(), "123456")

	var referenceError *ReferenceDataError
	if !errors.As(err, &referenceError) || referenceError.Retries != 2 || referenceError.Reference != protocol.ApplicationPIN {
		t.Fatalf("error = %v, want ReferenceDataError with two retries", err)
	}

	var apduError *iso7816.APDUError
	if !errors.As(err, &apduError) || apduError.StatusWord() != 0x63c2 {
		t.Errorf("error = %v, want underlying APDU status", err)
	}

	if strings.Contains(err.Error(), "123456") {
		t.Errorf("error contains PIN: %v", err)
	}
}

func TestInvalidPINDoesNotConsumeRetry(t *testing.T) {
	for _, pin := range []string{"12345", "123456789", "12345a", "１２３４５６"} {
		t.Run(pin, func(t *testing.T) {
			c := NewClient(newScript(t))
			if err := c.VerifyPIN(t.Context(), pin); err == nil {
				t.Fatal("expected invalid PIN encoding")
			}
		})
	}
}

func TestChangePIN(t *testing.T) {
	command := append([]byte{0, 0x24, 0, 0x80, 16}, []byte("12345678")...)
	command = append(command, []byte("87654321")...)

	c := NewClient(newScript(t, exchangeStep{command: command, response: iso7816.Response{Status: 0x9000}}))
	if err := c.ChangePIN(t.Context(), "12345678", "87654321"); err != nil {
		t.Fatal(err)
	}
}

func TestUnblockPINReportsPUKRetries(t *testing.T) {
	puk := [8]byte{0, 1, 2, 3, 4, 5, 6, 7}
	command := append([]byte{0, 0x2c, 0, 0x80, 16}, puk[:]...)
	command = append(command, []byte("12345678")...)
	c := NewClient(newScript(t, exchangeStep{command: command, response: iso7816.Response{Status: 0x63c1}}))
	err := c.UnblockPIN(t.Context(), puk, "12345678")

	var referenceError *ReferenceDataError
	if !errors.As(err, &referenceError) || referenceError.Reference != protocol.PUK || referenceError.Retries != 1 {
		t.Fatalf("error = %v, want PUK error with one retry", err)
	}

	if !bytes.Equal(puk[:], []byte{0, 1, 2, 3, 4, 5, 6, 7}) {
		t.Error("caller PUK was modified")
	}
}
