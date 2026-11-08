package client

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
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

func TestGenerateExtensionKeyPair(t *testing.T) {
	modulus := bytes.Repeat([]byte{0xab}, 512)
	rsaData := append([]byte{0x7f, 0x49, 0x82, 0x02, 0x09, 0x81, 0x82, 0x02, 0x00}, modulus...)
	rsaData = append(rsaData, 0x82, 0x03, 0x01, 0x00, 0x01)
	curve := elliptic.P521()
	point := make([]byte, 133)
	point[0] = 4
	curve.Params().Gx.FillBytes(point[1:67])
	curve.Params().Gy.FillBytes(point[67:])
	eccData := append([]byte{0x7f, 0x49, 0x81, 0x88, 0x86, 0x81, 0x85}, point...)
	public25519 := bytes.Repeat([]byte{0x42}, 32)
	data25519 := append([]byte{0x7f, 0x49, 0x22, 0x86, 0x20}, public25519...)

	for _, tc := range []struct {
		name      string
		algorithm protocol.Algorithm
		id        byte
		response  []byte
	}{
		{name: "RSA-4096", algorithm: protocol.RSA4096, id: 0x16, response: rsaData},
		{name: "P-521", algorithm: protocol.ECCP521, id: 0x15, response: eccData},
		{name: "Ed25519", algorithm: protocol.Ed25519, id: 0xe0, response: data25519},
		{name: "X25519", algorithm: protocol.X25519, id: 0xe1, response: data25519},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient(newScript(t, exchangeStep{
				command:  []byte{0, 0x47, 0, 0x9a, 5, 0xac, 3, 0x80, 1, tc.id, 0},
				response: iso7816.Response{Status: 0x9000, Data: tc.response},
			}))

			publicKey, err := c.GenerateAsymmetricKeyPair(t.Context(), protocol.GenerateAsymmetricKeyPairRequest{
				Key: protocol.PIVAuthentication, Algorithm: tc.algorithm,
			})
			if err != nil {
				t.Fatal(err)
			}

			switch key := publicKey.(type) {
			case *rsa.PublicKey:
				if tc.algorithm != protocol.RSA4096 || key.N.BitLen() != 4096 || key.E != 65537 {
					t.Errorf("generated key = %v, want RSA-4096", key)
				}
			case *ecdsa.PublicKey:
				if tc.algorithm != protocol.ECCP521 || key.Curve != elliptic.P521() {
					t.Errorf("generated key = %v, want P-521", key)
				}
			case ed25519.PublicKey:
				if tc.algorithm != protocol.Ed25519 || !bytes.Equal(key, public25519) {
					t.Errorf("generated key = %x, want Ed25519 %x", key, public25519)
				}
			case *ecdh.PublicKey:
				if tc.algorithm != protocol.X25519 || key.Curve() != ecdh.X25519() || !bytes.Equal(key.Bytes(), public25519) {
					t.Errorf("generated key = %v, want X25519 %x", key, public25519)
				}
			default:
				t.Fatalf("unexpected generated public key type %T", publicKey)
			}
		})
	}
}

func TestGenerateInvalidExtensionKeyReportsReplacement(t *testing.T) {
	for _, algorithm := range []protocol.Algorithm{protocol.Ed25519, protocol.X25519} {
		t.Run("invalid public key length", func(t *testing.T) {
			data := append([]byte{0x7f, 0x49, 0x21, 0x86, 0x1f}, make([]byte, 31)...)
			c := NewClient(newScript(t, exchangeStep{
				command:  []byte{0, 0x47, 0, 0x9c, 5, 0xac, 3, 0x80, 1, byte(algorithm), 0},
				response: iso7816.Response{Status: 0x9000, Data: data},
			}))

			key, err := c.GenerateAsymmetricKeyPair(t.Context(), protocol.GenerateAsymmetricKeyPairRequest{
				Key: protocol.DigitalSignature, Algorithm: algorithm,
			})

			var generated *KeyGenerationError
			if key != nil || !errors.As(err, &generated) || !errors.Is(err, protocol.ErrInvalidResponse) {
				t.Fatalf("GenerateAsymmetricKeyPair = %v, %v; want acknowledged replacement and ErrInvalidResponse", key, err)
			}

			if generated.Key != protocol.DigitalSignature || generated.Algorithm != algorithm {
				t.Errorf("generation error = %+v, want key 9C and algorithm %02x", generated, byte(algorithm))
			}
		})
	}
}
