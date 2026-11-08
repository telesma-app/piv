package client

import (
	"bytes"
	"errors"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
)

func TestVerifyCommandModes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request protocol.VerifyRequest
		command []byte
	}{
		{
			name:    "status query",
			request: protocol.VerifyRequest{Reference: protocol.ApplicationPIN},
			command: []byte{0, 0x20, 0, 0x80},
		},
		{
			name:    "reset security status",
			request: protocol.VerifyRequest{Reference: protocol.ApplicationPIN, ResetSecurityStatus: true},
			command: []byte{0, 0x20, 0xff, 0x80},
		},
		{
			name: "encoded OCC data",
			request: protocol.VerifyRequest{
				Reference: protocol.PrimaryFingerOCC, Data: []byte{1, 2, 3, 4, 5, 6},
			},
			command: []byte{0, 0x20, 0, 0x96, 6, 1, 2, 3, 4, 5, 6},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient(newScript(t, exchangeStep{
				command: tc.command, response: iso7816.Response{Status: 0x9000},
			}))
			original := bytes.Clone(tc.request.Data)

			if err := c.Verify(t.Context(), tc.request); err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(tc.request.Data, original) {
				t.Error("VERIFY changed borrowed reference data")
			}
		})
	}
}

func TestVerifyDistinguishesUnknownAndZeroRetries(t *testing.T) {
	for _, status := range []iso7816.StatusWord{0x6983, 0x63c0} {
		t.Run(status.String(), func(t *testing.T) {
			c := NewClient(newScript(t, exchangeStep{
				command: []byte{0, 0x20, 0, 0x80}, response: iso7816.Response{Status: status},
			}))

			err := c.Verify(t.Context(), protocol.VerifyRequest{Reference: protocol.ApplicationPIN})

			var apduError *iso7816.APDUError
			if !errors.As(err, &apduError) || apduError.StatusWord() != status {
				t.Fatalf("Verify = %v, want APDU status %s", err, status)
			}

			var referenceError *ReferenceDataError
			if status == 0x63c0 {
				if !errors.As(err, &referenceError) || referenceError.Retries != 0 {
					t.Fatalf("Verify = %v, want explicit zero retries", err)
				}
			} else if errors.As(err, &referenceError) {
				t.Fatalf("Verify inferred a retry count from status %s", status)
			}
		})
	}
}

func TestResetRetryCounterPreservesEncodedValues(t *testing.T) {
	puk := [8]byte{1, 2, 3, 4, 5, 6, 0xff, 0xff}
	replacement := [8]byte{8, 7, 6, 5, 4, 3, 2, 1}
	c := NewClient(newScript(t, exchangeStep{
		command:  []byte{0, 0x2c, 0, 0x80, 16, 1, 2, 3, 4, 5, 6, 0xff, 0xff, 8, 7, 6, 5, 4, 3, 2, 1},
		response: iso7816.Response{Status: 0x9000},
	}))

	if err := c.ResetRetryCounter(t.Context(), puk, replacement); err != nil {
		t.Fatal(err)
	}

	if puk != [8]byte{1, 2, 3, 4, 5, 6, 0xff, 0xff} || replacement != [8]byte{8, 7, 6, 5, 4, 3, 2, 1} {
		t.Error("RESET RETRY COUNTER changed caller-owned values")
	}
}
