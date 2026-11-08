package card

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/telesma-app/piv/protocol"
)

func TestPINAuthenticationEncodesSelectedReference(t *testing.T) {
	for _, tc := range []struct {
		name      string
		reference protocol.KeyReference
	}{
		{name: "application PIN", reference: protocol.ApplicationPIN},
		{name: "global PIN", reference: protocol.GlobalPIN},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			source := func(ctx context.Context) (string, error) {
				if ctx != t.Context() {
					t.Error("PIN source received a substituted context")
				}

				calls++

				return "123456", nil
			}
			authentication := PINAuthentication(tc.reference, source)

			if calls != 0 {
				t.Fatal("creating the authentication source requested a PIN")
			}

			for range 2 {
				request, err := authentication(t.Context())
				if err != nil {
					t.Fatal(err)
				}

				if request.Reference != tc.reference || request.ResetSecurityStatus ||
					!bytes.Equal(request.Data, []byte{'1', '2', '3', '4', '5', '6', 0xff, 0xff}) {
					t.Errorf("VERIFY request = %+v, want encoded PIN for reference %02x", request, tc.reference)
				}

				clear(request.Data)
			}

			if calls != 2 {
				t.Errorf("PIN source calls = %d, want 2", calls)
			}
		})
	}
}

func TestPINAuthenticationRejectsInvalidPIN(t *testing.T) {
	for _, pin := range []string{"", "12345", "12345a"} {
		t.Run(pin, func(t *testing.T) {
			authentication := PINAuthentication(protocol.ApplicationPIN, func(context.Context) (string, error) {
				return pin, nil
			})

			request, err := authentication(t.Context())
			if err == nil || request.Reference != 0 || request.ResetSecurityStatus || request.Data != nil {
				t.Errorf("PIN authentication = %+v, %v; want an encoding error without a VERIFY request", request, err)
			}
		})
	}
}

func TestPINAuthenticationPreservesSourceError(t *testing.T) {
	cause := errors.New("PIN prompt canceled")
	authentication := PINAuthentication(protocol.ApplicationPIN, func(context.Context) (string, error) {
		return "", cause
	})

	request, err := authentication(t.Context())
	if !errors.Is(err, cause) || request.Reference != 0 || request.ResetSecurityStatus || request.Data != nil {
		t.Errorf("PIN authentication = %+v, %v; want the source error without a VERIFY request", request, err)
	}
}
