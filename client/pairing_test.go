package client

import (
	"errors"
	"strings"
	"testing"

	"github.com/telesma-app/iso7816"
)

func TestVerifyPairingCode(t *testing.T) {
	for _, status := range []iso7816.StatusWord{0x9000, 0x6300} {
		t.Run(status.String(), func(t *testing.T) {
			c := NewClient(newScript(t, exchangeStep{
				command:  []byte{0, 0x20, 0, 0x98, 8, '6', '5', '1', '3', '5', '2', '7', '5'},
				response: iso7816.Response{Status: status},
			}))

			err := c.VerifyPairingCode(t.Context(), "65135275")
			if status == 0x9000 {
				if err != nil {
					t.Fatal(err)
				}

				return
			}

			var apduError *iso7816.APDUError
			if !errors.As(err, &apduError) || apduError.StatusWord() != 0x6300 {
				t.Fatalf("VerifyPairingCode = %v, want APDU status 6300", err)
			}

			var referenceError *ReferenceDataError
			if errors.As(err, &referenceError) {
				t.Fatal("pairing failure reported a retry counter")
			}

			if strings.Contains(err.Error(), "65135275") {
				t.Fatalf("pairing failure contains the code: %v", err)
			}
		})
	}
}

func TestVerifyPairingCodeRejectsInvalidEncodingBeforeIO(t *testing.T) {
	for _, code := range []string{"", "1234567", "123456789", "1234567a", "１２３４５６７８"} {
		t.Run(code, func(t *testing.T) {
			c := NewClient(newScript(t))
			if err := c.VerifyPairingCode(t.Context(), code); err == nil {
				t.Fatal("accepted invalid pairing code")
			}
		})
	}
}
