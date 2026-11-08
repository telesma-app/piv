package card

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/client"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

func expectCertificateWrite(t testing.TB, command iso7816.Command) {
	t.Helper()

	raw, err := command.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	want := []byte{0, 0xdb, 0x3f, 0xff, 16, 0x5c, 3, 0x5f, 0xc1, 0x0a, 0x53, 9, 0x70, 2, 0x30, 0, 0x71, 1, 0, 0xfe, 0}
	if !bytes.Equal(raw, want) {
		t.Errorf("PUT certificate = %x, want %x", raw, want)
	}
}

func rsa3072Response() iso7816.Response {
	modulus := bytes.Repeat([]byte{0xab}, 384)
	data := append([]byte{0x7f, 0x49, 0x82, 1, 0x89, 0x81, 0x82, 1, 0x80}, modulus...)

	return iso7816.Response{Status: 0x9000, Data: append(data, 0x82, 3, 1, 0, 1)}
}

func TestPutCertificateMutuallyAuthenticatesAllAdministrationAlgorithms(t *testing.T) {
	for _, vector := range administrationVectors {
		t.Run(vector.name, func(t *testing.T) {
			d, raw := newAdministrationPeer(t, vector)
			raw.effect = func(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
				expectCertificateWrite(t, command)
				return iso7816.Response{Status: 0x9000}, nil
			}
			originalKey := bytes.Clone(raw.key.Key)
			der := []byte{0x30, 0}

			for range 2 {
				if err := d.PutCertificate(t.Context(), protocol.DigitalSignature, der, raw.key); err != nil {
					t.Fatal(err)
				}
			}

			if raw.authentications != 2 || raw.effects != 2 || len(raw.requests) != 6 {
				t.Errorf("calls: authentications=%d effects=%d APDUs=%d, want 2, 2, 6", raw.authentications, raw.effects, len(raw.requests))
			}

			wantWitness := []byte{0, 0x87, byte(vector.algorithm), 0x9b, 4, 0x7c, 2, 0x80, 0, 0}
			if !bytes.Equal(raw.requests[0], wantWitness) {
				t.Errorf("witness request = %x, want %x", raw.requests[0], wantWitness)
			}

			if bytes.Equal(raw.challenges[0], raw.challenges[1]) {
				t.Error("mutual authentication reused its random challenge")
			}

			if !bytes.Equal(raw.key.Key, originalKey) || !bytes.Equal(der, []byte{0x30, 0}) {
				t.Error("administrative operation changed caller-owned input")
			}
		})
	}
}

func TestPutDataAuthenticatesBeforeWritingObject(t *testing.T) {
	for _, tc := range []struct {
		name    string
		object  protocol.Object
		command []byte
	}{
		{
			name: "CCC", object: protocol.CardCapabilityContainer,
			command: []byte{0, 0xdb, 0x3f, 0xff, 9, 0x5c, 3, 0x5f, 0xc1, 7, 0x53, 2, 1, 2},
		},
		{
			name: "discovery", object: protocol.DiscoveryObject,
			command: []byte{0, 0xdb, 0x3f, 0xff, 4, 0x7e, 2, 1, 2},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, raw := newAdministrationPeer(t, administrationVectors[0])
			raw.effect = func(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
				encoded, err := command.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}

				if !bytes.Equal(encoded, tc.command) {
					t.Errorf("PUT DATA = %x, want %x", encoded, tc.command)
				}

				return iso7816.Response{Status: 0x9000}, nil
			}
			data := []byte{1, 2}

			if err := d.PutData(t.Context(), tc.object, data, raw.key); err != nil {
				t.Fatal(err)
			}

			if raw.authentications != 1 || raw.effects != 1 || len(raw.requests) != 3 {
				t.Errorf("authentication and write counts = %d, %d, %d", raw.authentications, raw.effects, len(raw.requests))
			}

			if !bytes.Equal(data, []byte{1, 2}) {
				t.Error("PutData changed borrowed object data")
			}
		})
	}
}

func TestGenerateRSA3072AuthenticatesBeforeReplacement(t *testing.T) {
	d, raw := newAdministrationPeer(t, administrationVectors[0])
	raw.effect = func(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
		encoded, err := command.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}

		if want := []byte{0, 0x47, 0, 0x9a, 10, 0xac, 8, 0x80, 1, 5, 0x81, 3, 1, 0, 1, 0}; !bytes.Equal(encoded, want) {
			t.Errorf("GENERATE = %x, want %x", encoded, want)
		}

		return rsa3072Response(), nil
	}

	publicKey, err := d.GenerateAsymmetricKeyPair(t.Context(), protocol.GenerateAsymmetricKeyPairRequest{
		Key: protocol.PIVAuthentication, Algorithm: protocol.RSA3072, Parameter: []byte{1, 0, 1},
	}, raw.key)
	if err != nil {
		t.Fatal(err)
	}

	key, ok := publicKey.(*rsa.PublicKey)
	if !ok || key.N.BitLen() != 3072 || key.E != 65537 {
		t.Errorf("generated key = %v, want RSA-3072", publicKey)
	}

	if raw.authentications != 1 || raw.effects != 1 || len(raw.requests) != 3 {
		t.Errorf("authentication and generation counts = %d, %d, %d", raw.authentications, raw.effects, len(raw.requests))
	}
}

func TestGenerateExtensionKeyAuthenticatesBeforeReplacement(t *testing.T) {
	modulus := bytes.Repeat([]byte{0xab}, 512)
	rsaData := append([]byte{0x7f, 0x49, 0x82, 0x02, 0x09, 0x81, 0x82, 0x02, 0x00}, modulus...)
	rsaData = append(rsaData, 0x82, 0x03, 0x01, 0x00, 0x01)
	curve := elliptic.P521()
	point := make([]byte, 133)
	point[0] = 4
	curve.Params().Gx.FillBytes(point[1:67])
	curve.Params().Gy.FillBytes(point[67:])
	eccData := append([]byte{0x7f, 0x49, 0x81, 0x88, 0x86, 0x81, 0x85}, point...)
	data25519 := append([]byte{0x7f, 0x49, 0x22, 0x86, 0x20}, bytes.Repeat([]byte{0x42}, 32)...)

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
			d, raw := newAdministrationPeer(t, administrationVectors[0])
			raw.effect = func(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
				encoded, err := command.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}

				if want := []byte{0, 0x47, 0, 0x9a, 5, 0xac, 3, 0x80, 1, tc.id, 0}; !bytes.Equal(encoded, want) {
					t.Errorf("GENERATE = %x, want %x", encoded, want)
				}

				return iso7816.Response{Status: 0x9000, Data: tc.response}, nil
			}

			_, err := d.GenerateAsymmetricKeyPair(t.Context(), protocol.GenerateAsymmetricKeyPairRequest{
				Key: protocol.PIVAuthentication, Algorithm: tc.algorithm,
			}, raw.key)
			if err != nil {
				t.Fatal(err)
			}

			if raw.authentications != 1 || raw.effects != 1 || len(raw.requests) != 3 {
				t.Errorf("authentication and generation counts = %d, %d, %d", raw.authentications, raw.effects, len(raw.requests))
			}
		})
	}
}

func TestAdministrationKeyPreflightDoesNotAuthenticate(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  AdministrationKey
	}{
		{name: "legacy Triple-DES length", key: AdministrationKey{Algorithm: protocol.TripleDESLegacy, Key: make([]byte, 16)}},
		{name: "asymmetric mechanism", key: AdministrationKey{Algorithm: protocol.RSA2048, Key: make([]byte, 24)}},
		{name: "Triple-DES length", key: AdministrationKey{Algorithm: protocol.TripleDES, Key: make([]byte, 16)}},
		{name: "AES-128 with AES-192 length", key: AdministrationKey{Algorithm: protocol.AES128, Key: make([]byte, 24)}},
		{name: "AES-192 with AES-256 length", key: AdministrationKey{Algorithm: protocol.AES192, Key: make([]byte, 32)}},
		{name: "AES-256 with AES-128 length", key: AdministrationKey{Algorithm: protocol.AES256, Key: make([]byte, 16)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _ := newDevice(t)
			if err := d.PutCertificate(t.Context(), protocol.DigitalSignature, []byte{0x30, 0}, tc.key); err == nil {
				t.Fatal("expected administration key error before I/O")
			}
		})
	}
}

func TestUnsupportedGenerationDoesNotAuthenticate(t *testing.T) {
	d, _ := newDevice(t)

	key := AdministrationKey{Algorithm: protocol.AES128, Key: make([]byte, 16)}
	if _, err := d.GenerateAsymmetricKeyPair(t.Context(), protocol.GenerateAsymmetricKeyPairRequest{Key: protocol.PIVAuthentication, Algorithm: protocol.AES128}, key); err == nil {
		t.Fatal("expected unsupported generation algorithm before I/O")
	}
}

func TestAdministrationProofFailuresCloseSessionWithoutWriting(t *testing.T) {
	extraWitness := administrationReply(0x80, administrationBytes(t, administrationVectors[0].ciphertext)).Data
	extraWitness[1] += 2

	extraWitness = append(extraWitness, 0x82, 0)
	for _, tc := range []struct {
		name    string
		witness []byte
		proof   func([]byte) iso7816.Response
		want    error
	}{
		{name: "empty witness reply", witness: []byte{}, want: protocol.ErrInvalidResponse},
		{name: "short witness", witness: []byte{0x7c, 3, 0x80, 1, 0}, want: protocol.ErrInvalidResponse},
		{name: "malformed witness template", witness: []byte{0x7c, 4, 0x80}, want: protocol.ErrInvalidResponse},
		{
			name: "unexpected witness field", witness: extraWitness,
			want: protocol.ErrInvalidResponse,
		},
		{
			name: "wrong token proof", want: ErrAdministrationAuthentication,
			proof: func(proof []byte) iso7816.Response { proof[0] ^= 1; return administrationReply(0x82, proof) },
		},
		{name: "missing token proof", want: protocol.ErrInvalidResponse, proof: func([]byte) iso7816.Response { return iso7816.Response{Status: 0x9000} }},
		{name: "short token proof", want: protocol.ErrInvalidResponse, proof: func([]byte) iso7816.Response { return administrationReply(0x82, []byte{1}) }},
		{
			name: "unexpected proof field", want: protocol.ErrInvalidResponse,
			proof: func(proof []byte) iso7816.Response {
				response := administrationReply(0x82, proof)
				response.Data[1] += 2
				response.Data = append(response.Data, 0x80, 0)

				return response
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, raw := newAdministrationPeer(t, administrationVectors[0])
			raw.witnessReply, raw.proofReply = tc.witness, tc.proof
			closeErr := errors.New("disconnect failed")
			raw.closeErr = closeErr

			err := d.PutCertificate(t.Context(), protocol.DigitalSignature, []byte{0x30, 0}, raw.key)

			var invalidated *transport.DeviceInvalidatedError
			if !errors.As(err, &invalidated) || !errors.Is(err, tc.want) || !errors.Is(err, closeErr) {
				t.Fatalf("PutCertificate = %v, want invalidation, %v, and close failure", err, tc.want)
			}

			if raw.effects != 0 || raw.closeCalls != 1 {
				t.Errorf("after proof failure: effects=%d closes=%d, want 0 and 1", raw.effects, raw.closeCalls)
			}

			if strings.Contains(err.Error(), administrationVectors[0].key) {
				t.Error("authentication error contains the administration key")
			}

			if _, err := d.Exchange(t.Context(), iso7816.Command{INS: 0xfd}); !errors.Is(err, io.ErrClosedPipe) {
				t.Errorf("Exchange after authentication failure = %v, want closed session", err)
			}
		})
	}
}

func TestAdministrationAPDURejectionPreservesSessionWithoutWriting(t *testing.T) {
	for _, step := range []int{1, 2} {
		t.Run(string(rune('0'+step)), func(t *testing.T) {
			d, raw := newAdministrationPeer(t, administrationVectors[0])
			raw.reject = step

			err := d.PutCertificate(t.Context(), protocol.DigitalSignature, []byte{0x30, 0}, raw.key)

			var apdu *iso7816.APDUError
			if !errors.As(err, &apdu) || apdu.StatusWord() != 0x6982 {
				t.Fatalf("PutCertificate = %v, want APDU 6982", err)
			}

			if raw.effects != 0 || raw.closeCalls != 0 {
				t.Errorf("after rejection: effects=%d closes=%d, want 0 and 0", raw.effects, raw.closeCalls)
			}

			response, err := d.Exchange(t.Context(), iso7816.Command{INS: 0xfd})
			if err != nil || response.Status != 0x9000 {
				t.Errorf("Exchange after rejected authentication = %s, %v", response.Status, err)
			}
		})
	}
}

func TestAdministrativeWorkflowExcludesVendorExchange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d, raw := newAdministrationPeer(t, administrationVectors[0])
		proofStarted, proceed := make(chan struct{}), make(chan struct{})

		release := sync.OnceFunc(func() { close(proceed) })
		defer release()

		raw.afterProof = func() { close(proofStarted); <-proceed }
		raw.effect = func(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
			expectCertificateWrite(t, command)
			return iso7816.Response{Status: 0x9000}, nil
		}

		written := make(chan error, 1)
		go func() { written <- d.PutCertificate(t.Context(), protocol.DigitalSignature, []byte{0x30, 0}, raw.key) }()

		receive(t, proofStarted, "mutual authentication did not reach the token proof")

		vendor := make(chan error, 1)

		go func() { _, err := d.Exchange(t.Context(), iso7816.Command{INS: 0xfd}); vendor <- err }()

		synctest.Wait()

		if len(raw.requests) != 2 {
			t.Fatalf("APDU count during authentication = %d, want 2", len(raw.requests))
		}

		release()

		if err := receive(t, written, "certificate write did not finish"); err != nil {
			t.Fatal(err)
		}

		if err := receive(t, vendor, "queued vendor exchange did not finish"); err != nil {
			t.Fatal(err)
		}

		want := []byte{0x87, 0x87, 0xdb, 0xfd}

		var got []byte
		for _, request := range raw.requests {
			got = append(got, request[1])
		}

		if !bytes.Equal(got, want) {
			t.Errorf("command order = %x, want %x", got, want)
		}
	})
}

func TestCancelBetweenAuthenticationCommandsPreservesSession(t *testing.T) {
	for _, afterProof := range []bool{false, true} {
		name := "after witness"
		if afterProof {
			name = "after proof"
		}

		t.Run(name, func(t *testing.T) {
			d, raw := newAdministrationPeer(t, administrationVectors[0])

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			if afterProof {
				raw.afterProof = cancel
			} else {
				raw.afterWitness = cancel
			}

			err := d.PutCertificate(ctx, protocol.DigitalSignature, []byte{0x30, 0}, raw.key)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("PutCertificate = %v, want context cancellation", err)
			}

			wantRequests := 1
			if afterProof {
				wantRequests = 2
			}

			if len(raw.requests) != wantRequests || raw.effects != 0 || raw.closeCalls != 0 {
				t.Fatalf("canceled workflow: APDUs=%d effects=%d closes=%d", len(raw.requests), raw.effects, raw.closeCalls)
			}

			raw.afterWitness, raw.afterProof = nil, nil

			raw.effect = func(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
				expectCertificateWrite(t, command)
				return iso7816.Response{Status: 0x9000}, nil
			}
			if err := d.PutCertificate(t.Context(), protocol.DigitalSignature, []byte{0x30, 0}, raw.key); err != nil {
				t.Fatalf("fresh workflow after cancellation = %v", err)
			}
		})
	}
}

func TestCloseInterruptsAdministrativeAuthentication(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d, raw := newAdministrationPeer(t, administrationVectors[0])
		started := make(chan struct{})
		raw.afterWitness = func() { close(started); <-raw.closed }

		finished := make(chan error, 1)
		go func() { finished <- d.PutCertificate(t.Context(), protocol.DigitalSignature, []byte{0x30, 0}, raw.key) }()

		receive(t, started, "administrative authentication did not start")

		if err := d.Close(); err != nil {
			t.Fatal(err)
		}

		if err := receive(t, finished, "administrative authentication did not stop after Close"); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("PutCertificate = %v, want closed connection", err)
		}

		if raw.effects != 0 || raw.closeCalls != 1 {
			t.Errorf("after Close: effects=%d closes=%d", raw.effects, raw.closeCalls)
		}
	})
}

func TestGeneratedKeyRemainsAfterCertificateWriteFailure(t *testing.T) {
	d, raw := newAdministrationPeer(t, administrationVectors[0])

	var generated int

	raw.effect = func(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
		if command.INS == byte(protocol.GenerateAsymmetricKeyPair) {
			generated++
			return rsa3072Response(), nil
		}

		expectCertificateWrite(t, command)

		return iso7816.Response{Status: 0x6a84}, nil
	}

	publicKey, err := d.GenerateAsymmetricKeyPair(t.Context(), protocol.GenerateAsymmetricKeyPairRequest{Key: protocol.DigitalSignature, Algorithm: protocol.RSA3072}, raw.key)
	if err != nil {
		t.Fatal(err)
	}

	err = d.PutCertificate(t.Context(), protocol.DigitalSignature, []byte{0x30, 0}, raw.key)

	var apdu *iso7816.APDUError
	if !errors.As(err, &apdu) || apdu.StatusWord() != 0x6a84 {
		t.Fatalf("PutCertificate = %v, want memory error 6A84", err)
	}

	if publicKey.(*rsa.PublicKey).N.BitLen() != 3072 || generated != 1 || raw.authentications != 2 || raw.effects != 2 {
		t.Errorf("partial success: generated=%d authentications=%d effects=%d", generated, raw.authentications, raw.effects)
	}
}

func TestAcknowledgedGenerationFailurePreservesReplacementResult(t *testing.T) {
	d, raw := newAdministrationPeer(t, administrationVectors[0])
	raw.effect = func(context.Context, iso7816.Command) (iso7816.Response, error) {
		return iso7816.Response{Status: 0x9000, Data: []byte{0x7f, 0x49, 0}}, nil
	}

	_, err := d.GenerateAsymmetricKeyPair(t.Context(), protocol.GenerateAsymmetricKeyPairRequest{Key: protocol.PIVAuthentication, Algorithm: protocol.RSA3072}, raw.key)

	var generated *client.KeyGenerationError
	if !errors.As(err, &generated) || !errors.Is(err, protocol.ErrInvalidResponse) || generated.Key != protocol.PIVAuthentication || generated.Algorithm != protocol.RSA3072 {
		t.Fatalf("GenerateAsymmetricKeyPair = %v, want acknowledged replacement with parsing failure", err)
	}

	if raw.effects != 1 || raw.closeCalls != 0 {
		t.Errorf("after malformed generated key: effects=%d closes=%d", raw.effects, raw.closeCalls)
	}
}
