package client

import (
	"bytes"
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
)

type authenticationRequestTransport struct {
	request []byte
}

func (s *authenticationRequestTransport) Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	s.request = command.Data
	return iso7816.Response{Status: 0x9000}, nil
}

func TestGeneralAuthenticateClearsOwnedRequest(t *testing.T) {
	raw := &authenticationRequestTransport{}
	c := NewClient(raw)
	witness := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	_, err := c.GeneralAuthenticate(t.Context(), protocol.TripleDES, protocol.CardApplicationAdministration, protocol.DynamicAuthentication{
		Witness: witness,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(raw.request) == 0 {
		t.Fatal("request was not captured")
	}

	if !bytes.Equal(raw.request, make([]byte, len(raw.request))) {
		t.Error("owned authentication request was not cleared")
	}

	if !bytes.Equal(witness, []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Error("GeneralAuthenticate cleared caller's borrowed witness")
	}
}

func TestGeneralAuthenticateClearsMalformedResponse(t *testing.T) {
	for _, tc := range []struct {
		name   string
		suffix []byte
	}{
		{name: "truncated field", suffix: []byte{0x81, 2, 1}},
		{name: "duplicate response", suffix: []byte{0x82, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := append([]byte{0x82, 32}, bytes.Repeat([]byte{0xa5}, 32)...)
			body = append(body, tc.suffix...)
			data := append([]byte{0x7c, byte(len(body))}, body...)
			c := NewClient(newScript(t, exchangeStep{
				command:  []byte{0, 0x87, 0x11, 0x9c, 9, 0x7c, 7, 0x82, 0, 0x81, 3, 1, 2, 3, 0},
				response: iso7816.Response{Status: 0x9000, Data: data},
			}))

			got, err := c.GeneralAuthenticate(t.Context(), protocol.ECCP256, protocol.DigitalSignature, protocol.DynamicAuthentication{
				Response: []byte{}, Challenge: []byte{1, 2, 3},
			})
			if !errors.Is(err, protocol.ErrInvalidResponse) || got.Response != nil {
				t.Fatalf("GeneralAuthenticate = %+v, %v; want invalid response", got, err)
			}

			if !bytes.Equal(data, make([]byte, len(data))) {
				t.Error("malformed response retained private-key material")
			}
		})
	}
}

func TestPutCertificateMapsAllSlots(t *testing.T) {
	for _, tc := range []struct {
		key       protocol.KeyReference
		objectTag byte
	}{
		{key: 0x9a, objectTag: 0x05},
		{key: 0x9c, objectTag: 0x0a},
		{key: 0x9d, objectTag: 0x0b},
		{key: 0x9e, objectTag: 0x01},
		{key: 0x82, objectTag: 0x0d},
		{key: 0x83, objectTag: 0x0e},
		{key: 0x84, objectTag: 0x0f},
		{key: 0x85, objectTag: 0x10},
		{key: 0x86, objectTag: 0x11},
		{key: 0x87, objectTag: 0x12},
		{key: 0x88, objectTag: 0x13},
		{key: 0x89, objectTag: 0x14},
		{key: 0x8a, objectTag: 0x15},
		{key: 0x8b, objectTag: 0x16},
		{key: 0x8c, objectTag: 0x17},
		{key: 0x8d, objectTag: 0x18},
		{key: 0x8e, objectTag: 0x19},
		{key: 0x8f, objectTag: 0x1a},
		{key: 0x90, objectTag: 0x1b},
		{key: 0x91, objectTag: 0x1c},
		{key: 0x92, objectTag: 0x1d},
		{key: 0x93, objectTag: 0x1e},
		{key: 0x94, objectTag: 0x1f},
		{key: 0x95, objectTag: 0x20},
	} {
		t.Run(fmt.Sprintf("%02x", tc.key), func(t *testing.T) {
			c := NewClient(newScript(t, exchangeStep{
				command: []byte{
					0, 0xdb, 0x3f, 0xff, 0x10,
					0x5c, 3, 0x5f, 0xc1, tc.objectTag,
					0x53, 9, 0x70, 2, 0x30, 0, 0x71, 1, 0, 0xfe, 0,
				},
				response: iso7816.Response{Status: 0x9000},
			}))
			// This is deliberately not an X.509 certificate: the write command
			// must preserve caller-encoded bytes without invoking its parser.
			der := []byte{0x30, 0}

			if err := c.PutCertificate(t.Context(), tc.key, der); err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(der, []byte{0x30, 0}) {
				t.Error("PutCertificate changed caller DER")
			}
		})
	}
}

func TestPutCertificatePreservesErrors(t *testing.T) {
	cause := errors.New("connection lost")
	for _, tc := range []struct {
		name     string
		response iso7816.Response
		err      error
	}{
		{name: "authentication required", response: iso7816.Response{Status: 0x6982}},
		{name: "insufficient space", response: iso7816.Response{Status: 0x6a84}},
		{name: "transport", err: cause},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient(newScript(t, exchangeStep{
				command: []byte{
					0, 0xdb, 0x3f, 0xff, 0x10,
					0x5c, 3, 0x5f, 0xc1, 0x0a,
					0x53, 9, 0x70, 2, 0x30, 0, 0x71, 1, 0, 0xfe, 0,
				},
				response: tc.response, err: tc.err,
			}))

			err := c.PutCertificate(t.Context(), protocol.DigitalSignature, []byte{0x30, 0})
			if tc.err != nil {
				if !errors.Is(err, cause) {
					t.Fatalf("PutCertificate = %v, want transport cause", err)
				}
			} else {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != tc.response.Status {
					t.Fatalf("PutCertificate = %v, want APDU %s", err, tc.response.Status)
				}
			}
		})
	}
}

func TestGenerateRSA3072(t *testing.T) {
	modulus := bytes.Repeat([]byte{0xa5}, 384)
	data := append([]byte{0x7f, 0x49, 0x82, 1, 0x89, 0x81, 0x82, 1, 0x80}, modulus...)
	data = append(data, 0x82, 3, 1, 0, 1)
	c := NewClient(newScript(t, exchangeStep{
		command:  []byte{0, 0x47, 0, 0x9a, 5, 0xac, 3, 0x80, 1, 5, 0},
		response: iso7816.Response{Status: 0x9000, Data: data},
	}))

	got, err := c.GenerateAsymmetricKeyPair(t.Context(), protocol.GenerateAsymmetricKeyPairRequest{Key: protocol.PIVAuthentication, Algorithm: protocol.RSA3072})
	if err != nil {
		t.Fatal(err)
	}

	key, ok := got.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T, want *rsa.PublicKey", got)
	}

	if key.N.BitLen() != 3072 || !bytes.Equal(key.N.Bytes(), modulus) || key.E != 65537 {
		t.Errorf("public key = %v, want RSA-3072 with exponent 65537", key)
	}
}

func TestGenerateAsymmetricKeyPairRSAParameter(t *testing.T) {
	modulus := bytes.Repeat([]byte{0xa5}, 384)
	data := append([]byte{0x7f, 0x49, 0x82, 1, 0x89, 0x81, 0x82, 1, 0x80}, modulus...)
	data = append(data, 0x82, 3, 1, 0, 1)

	for _, tc := range []struct {
		name      string
		parameter []byte
		command   []byte
		mismatch  bool
	}{
		{
			name: "explicit exponent", parameter: []byte{1, 0, 1},
			command: []byte{0, 0x47, 0, 0x9c, 10, 0xac, 8, 0x80, 1, 5, 0x81, 3, 1, 0, 1, 0},
		},
		{
			name: "leading zero", parameter: []byte{0, 1, 0, 1},
			command: []byte{0, 0x47, 0, 0x9c, 11, 0xac, 9, 0x80, 1, 5, 0x81, 4, 0, 1, 0, 1, 0},
		},
		{
			name: "card ignored exponent", parameter: []byte{1, 0, 3},
			command:  []byte{0, 0x47, 0, 0x9c, 10, 0xac, 8, 0x80, 1, 5, 0x81, 3, 1, 0, 3, 0},
			mismatch: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient(newScript(t, exchangeStep{
				command: tc.command, response: iso7816.Response{Status: 0x9000, Data: data},
			}))
			parameter := bytes.Clone(tc.parameter)

			publicKey, err := c.GenerateAsymmetricKeyPair(t.Context(), protocol.GenerateAsymmetricKeyPairRequest{
				Key: protocol.DigitalSignature, Algorithm: protocol.RSA3072, Parameter: parameter,
			})

			if !bytes.Equal(parameter, tc.parameter) {
				t.Error("generation changed the caller's exponent")
			}

			if tc.mismatch {
				var generated *KeyGenerationError
				if publicKey != nil || !errors.As(err, &generated) || !errors.Is(err, protocol.ErrInvalidResponse) {
					t.Fatalf("GenerateAsymmetricKeyPair = %v, %v; want acknowledged generation with mismatched exponent", publicKey, err)
				}

				if generated.Key != protocol.DigitalSignature || generated.Algorithm != protocol.RSA3072 {
					t.Errorf("generation error = %+v, want key 9C and RSA-3072", generated)
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			if key := publicKey.(*rsa.PublicKey); key.E != 65537 || !bytes.Equal(key.N.Bytes(), modulus) {
				t.Errorf("public key = %v, want requested exponent 65537", key)
			}
		})
	}
}

func TestGenerateAsymmetricKeyPairReportsAcknowledgedReplacement(t *testing.T) {
	c := NewClient(newScript(t, exchangeStep{
		command:  []byte{0, 0x47, 0, 0x9c, 5, 0xac, 3, 0x80, 1, 5, 0},
		response: iso7816.Response{Status: 0x9000, Data: []byte{0x53, 0}},
	}))

	key, err := c.GenerateAsymmetricKeyPair(t.Context(), protocol.GenerateAsymmetricKeyPairRequest{Key: protocol.DigitalSignature, Algorithm: protocol.RSA3072})

	var generated *KeyGenerationError
	if key != nil || !errors.As(err, &generated) || !errors.Is(err, protocol.ErrInvalidResponse) {
		t.Fatalf("GenerateAsymmetricKeyPair = %v, %v; want acknowledged generation with parsing error", key, err)
	}

	if generated.Key != protocol.DigitalSignature || generated.Algorithm != protocol.RSA3072 {
		t.Errorf("generation error = %+v, want key 9C and RSA-3072", generated)
	}

	if !errors.Is(generated.Err, protocol.ErrInvalidResponse) {
		t.Errorf("generation cause = %v, want ErrInvalidResponse", generated.Err)
	}
}

func TestGenerateAsymmetricKeyPairDoesNotClaimUnacknowledgedReplacement(t *testing.T) {
	cause := errors.New("response lost")
	for _, tc := range []struct {
		name     string
		response iso7816.Response
		err      error
	}{
		{name: "rejected", response: iso7816.Response{Status: 0x6982}},
		{name: "transport", err: cause},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient(newScript(t, exchangeStep{
				command:  []byte{0, 0x47, 0, 0x9c, 5, 0xac, 3, 0x80, 1, 5, 0},
				response: tc.response, err: tc.err,
			}))

			key, err := c.GenerateAsymmetricKeyPair(t.Context(), protocol.GenerateAsymmetricKeyPairRequest{Key: protocol.DigitalSignature, Algorithm: protocol.RSA3072})

			var generated *KeyGenerationError
			if key != nil || err == nil || errors.As(err, &generated) {
				t.Fatalf("GenerateAsymmetricKeyPair = %v, %v; must not claim acknowledged replacement", key, err)
			}

			if tc.err != nil {
				if !errors.Is(err, cause) {
					t.Fatalf("GenerateAsymmetricKeyPair = %v, want transport cause", err)
				}
			} else {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != tc.response.Status {
					t.Fatalf("GenerateAsymmetricKeyPair = %v, want APDU %s", err, tc.response.Status)
				}
			}
		})
	}
}
