package card

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rsa"
	"encoding/hex"
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

type administrationVector struct {
	name       string
	algorithm  protocol.Algorithm
	key        string
	witness    string
	ciphertext string
}

// AES vectors are from FIPS 197, Appendix C.1-C.3. The Triple-DES vector is
// encryptTripleDESTests ("abcdefgh12345678ABCDEFGH") in Go's crypto/des tests.
var administrationVectors = []administrationVector{
	{
		name: "AES-128", algorithm: protocol.AES128,
		key: "000102030405060708090a0b0c0d0e0f", witness: "00112233445566778899aabbccddeeff",
		ciphertext: "69c4e0d86a7b0430d8cdb78070b4c55a",
	},
	{
		name: "AES-192", algorithm: protocol.AES192,
		key: "000102030405060708090a0b0c0d0e0f1011121314151617", witness: "00112233445566778899aabbccddeeff",
		ciphertext: "dda97ca4864cdfe06eaf70a0ec0d7191",
	},
	{
		name: "AES-256", algorithm: protocol.AES256,
		key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", witness: "00112233445566778899aabbccddeeff",
		ciphertext: "8ea2b7ca516745bfeafc49904b496089",
	},
	{
		name: "Triple-DES", algorithm: protocol.TripleDES,
		key: "616263646566676831323334353637384142434445464748", witness: "3030303030303030",
		ciphertext: "e461b759688bff66",
	},
	{
		name: "Triple-DES legacy 00", algorithm: protocol.TripleDESLegacy,
		key: "616263646566676831323334353637384142434445464748", witness: "3030303030303030",
		ciphertext: "e461b759688bff66",
	},
}

func administrationBytes(t testing.TB, encoded string) []byte {
	t.Helper()

	b, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}

	return b
}

// administrationPeer models the two-command mutual authentication, independently
// checks its wire layout, and answers the random challenge using stdlib crypto.
type administrationPeer struct {
	t               testing.TB
	key             AdministrationKey
	block           cipher.Block
	witness         []byte
	encrypted       []byte
	requests        [][]byte
	challenges      [][]byte
	witnessReply    []byte
	proofReply      func([]byte) iso7816.Response
	reject          int
	phase           int
	authenticated   bool
	authentications int
	afterWitness    func()
	afterProof      func()
	effect          func(context.Context, iso7816.Command) (iso7816.Response, error)
	effects         int
	closed          chan struct{}
	closeCalls      int
	closeErr        error
}

func newAdministrationPeer(t testing.TB, vector administrationVector) (*Device, *administrationPeer) {
	t.Helper()
	key := AdministrationKey{Algorithm: vector.algorithm, Key: administrationBytes(t, vector.key)}

	var block cipher.Block

	var err error
	if vector.algorithm == protocol.TripleDESLegacy || vector.algorithm == protocol.TripleDES {
		block, err = des.NewTripleDESCipher(key.Key)
	} else {
		block, err = aes.NewCipher(key.Key)
	}

	if err != nil {
		t.Fatal(err)
	}

	raw := &administrationPeer{
		t: t, key: key, block: block,
		witness: administrationBytes(t, vector.witness), encrypted: administrationBytes(t, vector.ciphertext),
		closed: make(chan struct{}),
	}
	d := New(raw)

	t.Cleanup(func() { _ = d.Close() })

	return d, raw
}

func administrationReply(tag byte, value []byte) iso7816.Response {
	data := append([]byte{0x7c, byte(len(value) + 2), tag, byte(len(value))}, value...)
	return iso7816.Response{Status: 0x9000, Data: data}
}

func (p *administrationPeer) Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	p.t.Helper()

	if err := ctx.Err(); err != nil {
		return iso7816.Response{}, err
	}

	select {
	case <-p.closed:
		return iso7816.Response{}, &transport.DeviceInvalidatedError{Err: io.ErrClosedPipe}
	default:
	}

	raw, err := command.MarshalBinary()
	if err != nil {
		p.t.Error(err)
		return iso7816.Response{}, err
	}
	// MarshalBinary owns this snapshot; GeneralAuthenticate clears command.Data.
	p.requests = append(p.requests, raw)

	if command.INS == 0xfd {
		return iso7816.Response{Status: 0x9000}, nil
	}

	if command.INS != byte(protocol.GeneralAuthenticate) {
		if !p.authenticated {
			p.t.Error("administrative command ran without mutual authentication")
			return iso7816.Response{}, io.ErrUnexpectedEOF
		}

		p.effects++
		if p.effect == nil {
			p.t.Errorf("unexpected administrative command: %x", raw)
			return iso7816.Response{}, io.ErrUnexpectedEOF
		}

		return p.effect(ctx, command)
	}

	if command.P1 != byte(p.key.Algorithm) || command.P2 != 0x9b || command.Le != 256 {
		p.t.Errorf("administration APDU header = %x", raw[:4])
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	if bytes.Equal(command.Data, []byte{0x7c, 2, 0x80, 0}) {
		p.phase = 1

		p.authenticated = false
		if p.reject == 1 {
			return iso7816.Response{Status: 0x6982}, nil
		}

		if p.afterWitness != nil {
			p.afterWitness()
		}

		if p.witnessReply != nil {
			return iso7816.Response{Status: 0x9000, Data: p.witnessReply}, nil
		}

		return administrationReply(0x80, p.encrypted), nil
	}

	if p.phase != 1 {
		p.t.Error("administration completion was sent without a witness request")
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	n := p.block.BlockSize()

	data := command.Data
	if len(data) != 2*n+8 || !bytes.Equal(data[:4], []byte{0x7c, byte(2*n + 6), 0x80, byte(n)}) ||
		!bytes.Equal(data[4:4+n], p.witness) || !bytes.Equal(data[4+n:6+n], []byte{0x81, byte(n)}) ||
		!bytes.Equal(data[6+2*n:], []byte{0x82, 0}) {
		p.t.Errorf("invalid mutual authentication completion: %x", data)
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	p.phase = 0
	if p.reject == 2 {
		return iso7816.Response{Status: 0x6982}, nil
	}

	challenge := bytes.Clone(data[6+n : 6+2*n])
	p.challenges = append(p.challenges, challenge)
	proof := make([]byte, n)
	p.block.Encrypt(proof, challenge)
	p.authenticated = true

	p.authentications++
	if p.afterProof != nil {
		p.afterProof()
	}

	if p.proofReply != nil {
		return p.proofReply(proof), nil
	}

	return administrationReply(0x82, proof), nil
}

func (p *administrationPeer) Close() error {
	p.closeCalls++
	close(p.closed)

	return p.closeErr
}

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
