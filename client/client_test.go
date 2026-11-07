package client

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
)

func TestSelect(t *testing.T) {
	properties := []byte{
		0x61, 0x11, 0x4f, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
		0x79, 0x07, 0x4f, 0x05, 0xa0, 0x00, 0x00, 0x03, 0x08,
	}
	c := NewClient(newScript(t, exchangeStep{
		command:  []byte{0, 0xa4, 4, 0, 9, 0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0, 0},
		response: iso7816.Response{Status: 0x9000, Data: properties},
	}))

	got, err := c.Select(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got.AID, properties[4:10]) || !bytes.Equal(got.TagAllocationAuthorityAID, properties[14:]) {
		t.Errorf("application properties = %+v, want identifiers from SELECT", got)
	}
}

func TestSelectRejectsMalformedApplicationProperties(t *testing.T) {
	c := NewClient(newScript(t, exchangeStep{
		command:  []byte{0, 0xa4, 4, 0, 9, 0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0, 0},
		response: iso7816.Response{Status: 0x9000, Data: []byte{0x61, 2, 0x4f}},
	}))

	if _, err := c.Select(t.Context()); !errors.Is(err, protocol.ErrInvalidResponse) {
		t.Fatalf("Select error = %v, want ErrInvalidResponse", err)
	}
}

func TestGetData(t *testing.T) {
	for _, tc := range []struct {
		name     string
		object   protocol.Object
		command  []byte
		response []byte
	}{
		{"CCC", protocol.CardCapabilityContainer, []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 7, 0}, []byte{0x53, 2, 1, 2}},
		{"discovery", protocol.DiscoveryObject, []byte{0, 0xcb, 0x3f, 0xff, 3, 0x5c, 1, 0x7e, 0}, []byte{0x7e, 2, 1, 2}},
		{"BIT", protocol.BiometricInformationTemplates, []byte{0, 0xcb, 0x3f, 0xff, 4, 0x5c, 2, 0x7f, 0x61, 0}, []byte{0x7f, 0x61, 2, 1, 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient(newScript(t, exchangeStep{command: tc.command, response: iso7816.Response{Status: 0x9000, Data: tc.response}}))

			got, err := c.GetData(t.Context(), tc.object)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(got, []byte{1, 2}) {
				t.Errorf("data = %x, want 0102", got)
			}
		})
	}
}

func TestGetDataAbsent(t *testing.T) {
	c := NewClient(newScript(t, exchangeStep{
		command:  []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 5, 0},
		response: iso7816.Response{Status: 0x6a82},
	}))
	_, err := c.GetData(t.Context(), protocol.PIVAuthenticationCertificate)

	var apdu *iso7816.APDUError
	if !errors.As(err, &apdu) || apdu.StatusWord() != 0x6a82 {
		t.Fatalf("error = %v, want APDU 6A82", err)
	}
}

func TestGetDataMalformed(t *testing.T) {
	c := NewClient(newScript(t, exchangeStep{
		command:  []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 7, 0},
		response: iso7816.Response{Status: 0x9000, Data: []byte{0x53, 2, 1}},
	}))

	_, err := c.GetData(t.Context(), protocol.CardCapabilityContainer)
	if !errors.Is(err, protocol.ErrInvalidResponse) {
		t.Fatalf("error = %v, want ErrInvalidResponse", err)
	}
}

func TestPutData(t *testing.T) {
	c := NewClient(newScript(t, exchangeStep{
		command:  []byte{0, 0xdb, 0x3f, 0xff, 9, 0x5c, 3, 0x5f, 0xc1, 7, 0x53, 2, 1, 2},
		response: iso7816.Response{Status: 0x9000},
	}))
	if err := c.PutData(t.Context(), protocol.CardCapabilityContainer, []byte{1, 2}); err != nil {
		t.Fatal(err)
	}
}

func TestPutDataSelfIdentifyingObjects(t *testing.T) {
	for _, tc := range []struct {
		name    string
		object  protocol.Object
		command []byte
	}{
		{"discovery", protocol.DiscoveryObject, []byte{0, 0xdb, 0x3f, 0xff, 4, 0x7e, 2, 1, 2}},
		{"BIT", protocol.BiometricInformationTemplates, []byte{0, 0xdb, 0x3f, 0xff, 5, 0x7f, 0x61, 2, 1, 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient(newScript(t, exchangeStep{command: tc.command, response: iso7816.Response{Status: 0x9000}}))
			if err := c.PutData(t.Context(), tc.object, []byte{1, 2}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPutDataRejectsUnexpectedResponseData(t *testing.T) {
	c := NewClient(newScript(t, exchangeStep{
		command:  []byte{0, 0xdb, 0x3f, 0xff, 9, 0x5c, 3, 0x5f, 0xc1, 7, 0x53, 2, 1, 2},
		response: iso7816.Response{Status: 0x9000, Data: []byte{1}},
	}))

	if err := c.PutData(t.Context(), protocol.CardCapabilityContainer, []byte{1, 2}); !errors.Is(err, protocol.ErrInvalidResponse) {
		t.Fatalf("PutData error = %v, want ErrInvalidResponse", err)
	}
}

func TestGeneralAuthenticate(t *testing.T) {
	digest := bytes.Repeat([]byte{0xa5}, 32)
	command := append([]byte{0, 0x87, 0x11, 0x9c, 0x26, 0x7c, 0x24, 0x82, 0, 0x81, 0x20}, digest...)
	command = append(command, 0)
	c := NewClient(newScript(t, exchangeStep{
		command:  command,
		response: iso7816.Response{Status: 0x9000, Data: []byte{0x7c, 4, 0x82, 2, 1, 2}},
	}))

	got, err := c.GeneralAuthenticate(t.Context(), protocol.ECCP256, protocol.DigitalSignature, protocol.DynamicAuthentication{
		Response: []byte{}, Challenge: digest,
	})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got.Response, []byte{1, 2}) {
		t.Errorf("response = %x, want 0102", got.Response)
	}
}

func TestGeneralAuthenticateSingleAdministrationCompletion(t *testing.T) {
	c := NewClient(newScript(t, exchangeStep{
		command:  []byte{0, 0x87, 3, 0x9b, 6, 0x7c, 4, 0x82, 2, 1, 2, 0},
		response: iso7816.Response{Status: 0x9000},
	}))

	got, err := c.GeneralAuthenticate(t.Context(), protocol.TripleDES, protocol.CardApplicationAdministration, protocol.DynamicAuthentication{
		Response: []byte{1, 2},
	})
	if err != nil {
		t.Fatal(err)
	}

	if got.Witness != nil || got.Challenge != nil || got.Response != nil || got.Exponentiation != nil {
		t.Errorf("completion = %+v, want empty authentication result", got)
	}
}

func TestGenerateAsymmetricKeyPair(t *testing.T) {
	curve := elliptic.P256()
	point := make([]byte, 65)
	point[0] = 4
	curve.Params().Gx.FillBytes(point[1:33])
	curve.Params().Gy.FillBytes(point[33:])
	data := append([]byte{0x7f, 0x49, 0x43, 0x86, 0x41}, point...)
	c := NewClient(newScript(t, exchangeStep{
		command:  []byte{0, 0x47, 0, 0x9a, 5, 0xac, 3, 0x80, 1, 0x11, 0},
		response: iso7816.Response{Status: 0x9000, Data: data},
	}))

	got, err := c.GenerateAsymmetricKeyPair(t.Context(), protocol.GenerateAsymmetricKeyPairRequest{Key: protocol.PIVAuthentication, Algorithm: protocol.ECCP256})
	if err != nil {
		t.Fatal(err)
	}

	key, ok := got.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T, want *ecdsa.PublicKey", got)
	}

	encoded, err := key.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(encoded, point) {
		t.Errorf("public key = %v, want P256 generator", got)
	}
}

func TestGenerateUnsupportedAlgorithmDoesNotOverwriteKey(t *testing.T) {
	c := NewClient(newScript(t))
	if _, err := c.GenerateAsymmetricKeyPair(t.Context(), protocol.GenerateAsymmetricKeyPairRequest{Key: protocol.PIVAuthentication, Algorithm: protocol.AES128}); err == nil {
		t.Fatal("expected unsupported key generation algorithm")
	}
}

func TestTransportErrorPreserved(t *testing.T) {
	want := errors.New("disconnected")
	c := NewClient(newScript(t, exchangeStep{
		command: []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 7, 0}, err: want,
	}))

	_, err := c.GetData(t.Context(), protocol.CardCapabilityContainer)
	if !errors.Is(err, want) {
		t.Errorf("error = %v, want underlying cause", err)
	}
}
