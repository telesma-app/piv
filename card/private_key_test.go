package card

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/client"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

// This fixed PKCS#8 fixture comes from Go's crypto/rsa rsa_test.go test2048Key.
// Parse it afresh so each test owns its mutable key state.
const signingRSAFixture = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDNoyFUYeDuqw+k
iyv47iBy/udbWmQdpbUZ8JobHv8uQrvL7sQN6l83teHgNJsXqtiLF3MC+K+XI6Dq
hxUWfQwLip8WEnv7Jx/+53S8yp/CS4Jw86Q1bQHbZjFDpcoqSuwAxlegw18HNZCY
fpipYnA1lYCm+MTjtgXJQbjA0dwUGCf4BDMqt+76Jk3XZF5975rftbkGoT9eu8Jt
Xs5F5Xkwd8q3fkQz+fpLW4u9jrfFyQ61RRFkYrCjlhtGjYIzBHGgQM4n/sNXhiy5
h0tA7Xa6NyYrN/OXe/Y1K8Rz/tzlvbMoxgZgtBuKo1N3m8ckFi7hUVK2eNv7GoAb
teTTPrg/AgMBAAECggEAAnfsVpmsL3R0Bh4gXRpPeM63H6e1a8B8kyVwiO9o0cXX
gKp9+P39izfB0Kt6lyCj/Wg+wOQT7rg5qy1yIw7fBHGmcjquxh3uN0s3YZ+Vcym6
SAY5f0vh/OyJN9r3Uv8+Pc4jtb7So7QDzdWeZurssBmUB0avAMRdGNFGP5SyILcz
l3Q59hTxQ4czRHKjZ06L1/sA+tFVbO1j39FN8nMOU/ovLF4lAmZTkQ6AP6n6XPHP
B8Nq7jSYz6RDO200jzp6UsdrnjjkJRbzOxN/fn+ckCP+WYuq+y/d05ET9PdVa4qI
Jyr80D9QgHmfztcecvYwoskGnkb2F4Tmp0WnAj/xVQKBgQD4TrMLyyHdbAr5hoSi
p+r7qBQxnHxPe2FKO7aqagi4iPEHauEDgwPIcsOYota1ACiSs3BaESdJAClbqPYd
HDI4c2DZ6opux6WYkSju+tVXYW6qarR3fzrP3fUCdz2c2NfruWOqq8YmjzAhTNPm
YzvtzTdwheNYV0Vi71t1SfZmfQKBgQDUAgSUcrgXdGDnSbaNe6KwjY5oZWOQfZe2
DUhqfN/JRFZj+EMfIIh6OQXnZqkp0FeRdfRAFl8Yz8ESHEs4j+TikLJEeOdfmYLS
TWxlMPDTUGbUvSf4g358NJ8TlfYA7dYpSTNPXMRSLtsz1palmaDBTE/V2xKtTH6p
VglRNRUKawKBgCPqBh2TkN9czC2RFkgMb4FcqycN0jEQ0F6TSnVVhtNiAzKmc8s1
POvWJZJDIzjkv/mP+JUeXAdD/bdjNc26EU126rA6KzGgsMPjYv9FymusDPybGGUc
Qt5j5RcpNgEkn/5ZPyAlXjCfjz+RxChTfAyGHRmqU9qoLMIFir3pJ7llAoGBAMNH
sIxENwlzqyafoUUlEq/pU7kZWuJmrO2FwqRDraYoCiM/NCRhxRQ/ng6NY1gejepw
abD2alXiV4alBSxubne6rFmhvA00y2mG40c6Ezmxn2ZpbX3dMQ6bMcPKp7QnXtLc
mCSL4FGK02ImUNDsd0RVVFw51DRId4rmsuJYMK9NAoGAKlYdc4784ixTD2ZICIOC
ZWPxPAyQUEA7EkuUhAX1bVNG6UJTYA8kmGcUCG4jPTgWzi00IyUUr8jK7efyU/zs
qiJuVs1bia+flYIQpysMl1VzZh8gW1nkB4SVPm5l2wBvVJDIr9Mc6rueC/oVNkh2
fLVGuFoTVIu2bF0cWAjNNMg=
-----END PRIVATE KEY-----`

func signingRSA(t testing.TB) *rsa.PrivateKey {
	t.Helper()

	block, _ := pem.Decode([]byte(signingRSAFixture))

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	return parsed.(*rsa.PrivateKey)
}

func signingECDSA(t testing.TB, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return key
}

// signaturePeer models a selected card's VERIFY and raw signature operations.
// Request snapshots own their bytes because client buffers are cleared on return.
type signaturePeer struct {
	t                       testing.TB
	reference               protocol.KeyReference
	algorithm               protocol.Algorithm
	authenticationReference protocol.KeyReference
	authenticationData      []byte
	ec                      *ecdsa.PrivateKey
	rsa                     *rsa.PrivateKey
	instructions            []byte
	inputs                  [][]byte
	verifies                int
	signatures              int
	statuses                int
	afterVerify             func()
	beforeSign              func(context.Context) error
	afterSignature          func()
	response                func([]byte) iso7816.Response
	closed                  chan struct{}
	closeCalls              int
}

func newECDSASigningPeer(t testing.TB, curve elliptic.Curve, reference protocol.KeyReference) (*PrivateKey, *signaturePeer) {
	t.Helper()
	private := signingECDSA(t, curve)

	algorithm := protocol.ECCP256
	if curve == elliptic.P384() {
		algorithm = protocol.ECCP384
	}

	raw := &signaturePeer{
		t: t, reference: reference, algorithm: algorithm, ec: private, closed: make(chan struct{}),
		authenticationReference: protocol.ApplicationPIN,
		authenticationData:      []byte{'1', '2', '3', '4', '5', '6', 0xff, 0xff},
	}
	device := New(raw)

	t.Cleanup(func() { _ = device.Close() })

	key, err := device.PrivateKey(reference, &private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	return key, raw
}

func newRSASigningPeer(t testing.TB) (*PrivateKey, *signaturePeer) {
	t.Helper()
	private := signingRSA(t)
	raw := &signaturePeer{
		t: t, reference: protocol.DigitalSignature, algorithm: protocol.RSA2048,
		rsa: private, closed: make(chan struct{}),
		authenticationReference: protocol.ApplicationPIN,
		authenticationData:      []byte{'1', '2', '3', '4', '5', '6', 0xff, 0xff},
	}
	device := New(raw)

	t.Cleanup(func() { _ = device.Close() })

	key, err := device.PrivateKey(protocol.DigitalSignature, &private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	return key, raw
}

func signatureTLV(tag byte, value []byte) []byte {
	if len(value) < 128 {
		return append([]byte{tag, byte(len(value))}, value...)
	}

	return append([]byte{tag, 0x82, byte(len(value) >> 8), byte(len(value))}, value...)
}

func signatureResponse(signature []byte) iso7816.Response {
	return iso7816.Response{Status: 0x9000, Data: signatureTLV(0x7c, signatureTLV(0x82, signature))}
}

func (p *signaturePeer) Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	p.t.Helper()

	if err := ctx.Err(); err != nil {
		return iso7816.Response{}, err
	}

	select {
	case <-p.closed:
		return iso7816.Response{}, &transport.DeviceInvalidatedError{Err: io.ErrClosedPipe}
	default:
	}

	p.instructions = append(p.instructions, command.INS)
	if command.INS == 0xfd {
		return iso7816.Response{Status: 0x9000}, nil
	}

	if command.INS == byte(protocol.Verify) {
		if command.P1 != 0 || command.P2 != byte(p.authenticationReference) {
			p.t.Errorf("VERIFY header = %+v", command)
			return iso7816.Response{}, io.ErrUnexpectedEOF
		}

		if len(command.Data) == 0 {
			p.statuses++
			return iso7816.Response{Status: 0x63c3}, nil
		}

		p.verifies++

		if !bytes.Equal(command.Data, p.authenticationData) {
			return iso7816.Response{Status: 0x63c2}, nil
		}

		if p.afterVerify != nil {
			p.afterVerify()
		}

		return iso7816.Response{Status: 0x9000}, nil
	}

	if command.INS != byte(protocol.GeneralAuthenticate) || command.P1 != byte(p.algorithm) ||
		command.P2 != byte(p.reference) || command.Le != 256 || command.CLA != 0 {
		p.t.Errorf("unexpected signing command: %+v", command)
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	var prefix []byte
	if p.rsa != nil {
		// Independent RSA-2048 wire oracle: 7C {82 empty, 81 256-byte EM}.
		prefix = []byte{0x7c, 0x82, 1, 6, 0x82, 0, 0x81, 0x82, 1, 0}
	} else {
		width := p.ec.Curve.Params().BitSize / 8
		prefix = []byte{0x7c, byte(width + 4), 0x82, 0, 0x81, byte(width)}
	}

	if !bytes.HasPrefix(command.Data, prefix) {
		p.t.Errorf("signing input prefix = %x, want %x", command.Data, prefix)
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	input := command.Data[len(prefix):]
	if p.rsa != nil && len(input) != p.rsa.Size() {
		p.t.Errorf("RSA input length = %d, want %d", len(input), p.rsa.Size())
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	if p.ec != nil && len(input) != p.ec.Curve.Params().BitSize/8 {
		p.t.Errorf("ECDSA input length = %d, want %d", len(input), p.ec.Curve.Params().BitSize/8)
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	p.inputs = append(p.inputs, bytes.Clone(input))
	if p.beforeSign != nil {
		if err := p.beforeSign(ctx); err != nil {
			return iso7816.Response{}, err
		}
	}

	var signature []byte
	if p.rsa != nil {
		// This is the token's raw RSA primitive, not the host EMSA encoder.
		signature = new(big.Int).Exp(new(big.Int).SetBytes(input), p.rsa.D, p.rsa.N).FillBytes(make([]byte, p.rsa.Size()))
	} else {
		var err error

		signature, err = ecdsa.SignASN1(rand.Reader, p.ec, input)
		if err != nil {
			p.t.Error(err)
			return iso7816.Response{}, err
		}
	}

	p.signatures++
	if p.afterSignature != nil {
		p.afterSignature()
	}

	if p.response != nil {
		return p.response(signature), nil
	}

	return signatureResponse(signature), nil
}

func (p *signaturePeer) Close() error {
	p.closeCalls++
	close(p.closed)

	return nil
}

func signingPIN(context.Context) (string, error) {
	return "123456", nil
}

func TestPrivateKeyBindingDoesNotPerformIOOrCopyPublicKey(t *testing.T) {
	for _, bits := range []int{1024, 2048, 3072} {
		t.Run(fmt.Sprintf("RSA-%d", bits), func(t *testing.T) {
			device, raw := newDevice(t)
			publicKey := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), uint(bits-1)), E: 65537}

			key, err := device.PrivateKey(protocol.DigitalSignature, publicKey)
			if err != nil {
				t.Fatal(err)
			}

			if key.Public() != publicKey || raw.calls != 0 {
				t.Error("binding copied the public key or performed I/O")
			}
		})
	}
}

func TestPrivateKeyRejectsUnsupportedAlgorithmsWithoutIO(t *testing.T) {
	for _, publicKey := range []crypto.PublicKey{
		ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)),
		&signingECDSA(t, elliptic.P521()).PublicKey,
		&rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2048), E: 65537},
	} {
		device, _ := newDevice(t)
		if _, err := device.PrivateKey(protocol.DigitalSignature, publicKey); err == nil {
			t.Fatalf("accepted unsupported key type %T", publicKey)
		}
	}
}

func TestECDSASignTruncatesDigestAndVerifiesEveryTime(t *testing.T) {
	digest := sha512.Sum512([]byte("PIV ECDSA input truncation"))

	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			key, raw := newECDSASigningPeer(t, curve, protocol.DigitalSignature)
			prompts := 0
			pin := func(context.Context) (string, error) { prompts++; return "123456", nil }

			for range 2 {
				signature, err := key.Sign(t.Context(), rand.Reader, digest[:], crypto.SHA512, PINAuthentication(protocol.ApplicationPIN, pin))
				if err != nil {
					t.Fatal(err)
				}

				if !ecdsa.VerifyASN1(&raw.ec.PublicKey, digest[:], signature) {
					t.Error("signature did not verify against the original full digest")
				}
			}

			if prompts != 2 || raw.verifies != 2 || raw.signatures != 2 || raw.statuses != 0 {
				t.Errorf("counts prompts/VERIFY/signatures/status = %d/%d/%d/%d", prompts, raw.verifies, raw.signatures, raw.statuses)
			}

			for _, input := range raw.inputs {
				if want := digest[:curve.Params().BitSize/8]; !bytes.Equal(input, want) {
					t.Errorf("ECDSA input = %x, want leftmost digest bytes %x", input, want)
				}
			}
		})
	}
}

func TestECDSASignPadsShortDigestsWithoutChangingInput(t *testing.T) {
	sha1Digest := sha1.Sum([]byte("PIV ECDSA short digest"))
	sha256Digest := sha256.Sum256([]byte("PIV ECDSA short digest"))

	for _, tc := range []struct {
		name    string
		curve   elliptic.Curve
		hash    crypto.Hash
		digest  []byte
		padding int
	}{
		{name: "SHA-1 with P-256", curve: elliptic.P256(), hash: crypto.SHA1, digest: sha1Digest[:], padding: 12},
		{name: "SHA-256 with P-384", curve: elliptic.P384(), hash: crypto.SHA256, digest: sha256Digest[:], padding: 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, raw := newECDSASigningPeer(t, tc.curve, protocol.DigitalSignature)
			digest := bytes.Clone(tc.digest)

			signature, err := key.Sign(t.Context(), rand.Reader, digest, tc.hash, PINAuthentication(protocol.ApplicationPIN, signingPIN))
			if err != nil {
				t.Fatal(err)
			}

			if !ecdsa.VerifyASN1(&raw.ec.PublicKey, tc.digest, signature) {
				t.Error("signature does not verify against the original unpadded digest")
			}

			want := append(make([]byte, tc.padding), tc.digest...)
			if len(raw.inputs) != 1 || !bytes.Equal(raw.inputs[0], want) {
				t.Errorf("ECDSA wire input = %x, want %x", raw.inputs, want)
			}

			if !bytes.Equal(digest, tc.digest) {
				t.Error("ECDSA preparation changed the borrowed digest")
			}

			if raw.verifies != 1 || raw.signatures != 1 {
				t.Errorf("VERIFY/signature counts = %d/%d, want 1/1", raw.verifies, raw.signatures)
			}
		})
	}
}

func TestNilAuthenticationSkipsVerifyAndEmptyPINDoesNot(t *testing.T) {
	key, raw := newECDSASigningPeer(t, elliptic.P256(), protocol.CardAuthentication)
	digest := sha256.Sum256([]byte("PIN never key"))

	if _, err := key.Sign(t.Context(), rand.Reader, digest[:], crypto.SHA256, nil); err != nil {
		t.Fatal(err)
	}

	if raw.verifies != 0 || raw.signatures != 1 {
		t.Errorf("without PIN: VERIFY/signatures = %d/%d", raw.verifies, raw.signatures)
	}

	empty := func(context.Context) (string, error) { return "", nil }
	if _, err := key.Sign(t.Context(), rand.Reader, digest[:], crypto.SHA256, PINAuthentication(protocol.ApplicationPIN, empty)); err == nil {
		t.Fatal("empty supplied PIN was silently treated as no VERIFY")
	}

	if len(raw.instructions) != 1 {
		t.Error("invalid supplied PIN performed I/O")
	}
}

func TestSigningUsesExplicitAuthenticationReferenceAndData(t *testing.T) {
	for _, tc := range []struct {
		name      string
		reference protocol.KeyReference
		data      []byte
	}{
		{name: "Global PIN", reference: protocol.GlobalPIN, data: []byte{'8', '7', '6', '5', '4', '3', 0xff, 0xff}},
		{name: "primary finger OCC", reference: protocol.PrimaryFingerOCC, data: bytes.Repeat([]byte{0x10, 0x80, 0xff}, 30)},
		{name: "secondary finger OCC", reference: protocol.SecondaryFingerOCC, data: bytes.Repeat([]byte{0x81, 0, 0x42}, 30)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, raw := newECDSASigningPeer(t, elliptic.P256(), protocol.DigitalSignature)
			raw.authenticationReference = tc.reference
			raw.authenticationData = tc.data
			digest := sha256.Sum256([]byte("explicit authentication"))
			requests := 0
			authentication := func(ctx context.Context) (protocol.VerifyRequest, error) {
				if ctx != t.Context() {
					t.Error("authentication source received a substituted context")
				}

				requests++

				return protocol.VerifyRequest{Reference: tc.reference, Data: bytes.Clone(tc.data)}, nil
			}

			for range 2 {
				signature, err := key.Sign(t.Context(), rand.Reader, digest[:], crypto.SHA256, authentication)
				if err != nil {
					t.Fatal(err)
				}

				if !ecdsa.VerifyASN1(&raw.ec.PublicKey, digest[:], signature) {
					t.Error("signature did not verify")
				}
			}

			if requests != 2 || raw.verifies != 2 || raw.signatures != 2 || raw.statuses != 0 {
				t.Errorf("source/VERIFY/signature/status counts = %d/%d/%d/%d", requests, raw.verifies, raw.signatures, raw.statuses)
			}
		})
	}
}

func TestPINAuthenticationSelectsGlobalPIN(t *testing.T) {
	key, raw := newECDSASigningPeer(t, elliptic.P256(), protocol.DigitalSignature)
	raw.authenticationReference = protocol.GlobalPIN
	digest := sha256.Sum256([]byte("global PIN encoding"))

	if _, err := key.Sign(t.Context(), rand.Reader, digest[:], crypto.SHA256, PINAuthentication(protocol.GlobalPIN, signingPIN)); err != nil {
		t.Fatal(err)
	}

	if raw.verifies != 1 || raw.signatures != 1 {
		t.Errorf("VERIFY/signature counts = %d/%d, want 1/1", raw.verifies, raw.signatures)
	}
}

func TestExplicitEmptyAuthenticationQueriesStatus(t *testing.T) {
	key, raw := newECDSASigningPeer(t, elliptic.P256(), protocol.DigitalSignature)
	raw.authenticationReference = protocol.GlobalPIN
	digest := sha256.Sum256([]byte("explicit authentication status query"))
	authentication := func(context.Context) (protocol.VerifyRequest, error) {
		return protocol.VerifyRequest{Reference: protocol.GlobalPIN}, nil
	}

	signature, err := key.Sign(t.Context(), rand.Reader, digest[:], crypto.SHA256, authentication)

	var referenceError *client.ReferenceDataError
	if signature != nil || !errors.As(err, &referenceError) || referenceError.Reference != protocol.GlobalPIN || referenceError.Retries != 3 {
		t.Fatalf("Sign = %x, %v; want Global PIN status with three retries", signature, err)
	}

	if raw.statuses != 1 || raw.verifies != 0 || raw.signatures != 0 {
		t.Errorf("status/VERIFY/signature counts = %d/%d/%d, want 1/0/0", raw.statuses, raw.verifies, raw.signatures)
	}
}

func TestSigningClearsOwnedAuthenticationData(t *testing.T) {
	for _, rejected := range []bool{false, true} {
		name := "success"
		if rejected {
			name = "VERIFY rejected"
		}

		t.Run(name, func(t *testing.T) {
			key, raw := newECDSASigningPeer(t, elliptic.P256(), protocol.DigitalSignature)
			raw.authenticationReference = protocol.GlobalPIN

			data := bytes.Clone(raw.authenticationData)
			if rejected {
				data[0] = '0'
			}

			authentication := func(context.Context) (protocol.VerifyRequest, error) {
				return protocol.VerifyRequest{Reference: protocol.GlobalPIN, Data: data}, nil
			}
			digest := sha256.Sum256([]byte("owned authentication data"))

			_, err := key.Sign(t.Context(), rand.Reader, digest[:], crypto.SHA256, authentication)
			if rejected {
				var referenceError *client.ReferenceDataError
				if !errors.As(err, &referenceError) || raw.signatures != 0 {
					t.Fatalf("Sign = %v, signatures=%d; want VERIFY rejection without signing", err, raw.signatures)
				}
			} else if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(data, make([]byte, len(data))) {
				t.Error("Sign retained owned authentication data")
			}
		})
	}
}

func TestQueuedSigningCancellationClearsAuthenticationData(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		key, raw := newECDSASigningPeer(t, elliptic.P256(), protocol.DigitalSignature)
		started, proceed := make(chan struct{}), make(chan struct{})

		release := sync.OnceFunc(func() { close(proceed) })
		defer release()

		raw.beforeSign = func(context.Context) error { close(started); <-proceed; return nil }
		digest := sha256.Sum256([]byte("queued authentication cleanup"))
		active := make(chan error, 1)

		go func() {
			_, err := key.Sign(t.Context(), rand.Reader, digest[:], crypto.SHA256, nil)
			active <- err
		}()

		receive(t, started, "active signature did not start")

		data := []byte{'1', '2', '3', '4', '5', '6', 0xff, 0xff}
		sourced := make(chan struct{})
		authentication := func(context.Context) (protocol.VerifyRequest, error) {
			close(sourced)
			return protocol.VerifyRequest{Reference: protocol.GlobalPIN, Data: data}, nil
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		queued := make(chan error, 1)

		go func() {
			_, err := key.Sign(ctx, rand.Reader, digest[:], crypto.SHA256, authentication)
			queued <- err
		}()

		receive(t, sourced, "queued signature did not obtain authentication data")
		synctest.Wait()
		cancel()

		if err := receive(t, queued, "queued signature ignored cancellation"); !errors.Is(err, context.Canceled) {
			t.Fatalf("queued Sign = %v, want cancellation", err)
		}

		if !bytes.Equal(data, make([]byte, len(data))) {
			t.Error("canceled Sign retained owned authentication data")
		}

		if raw.verifies != 0 || len(raw.instructions) != 1 || raw.closeCalls != 0 {
			t.Errorf("queued cancellation changed active session: VERIFY/instructions/closes=%d/%x/%d", raw.verifies, raw.instructions, raw.closeCalls)
		}

		release()

		if err := receive(t, active, "active signature did not finish"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestWrongPINDoesNotSignOrRetry(t *testing.T) {
	key, raw := newECDSASigningPeer(t, elliptic.P256(), protocol.DigitalSignature)
	digest := sha256.Sum256([]byte("wrong PIN"))
	wrong := func(context.Context) (string, error) { return "000000", nil }

	signature, err := key.Sign(t.Context(), rand.Reader, digest[:], crypto.SHA256, PINAuthentication(protocol.ApplicationPIN, wrong))

	var referenceError *client.ReferenceDataError
	if signature != nil || !errors.As(err, &referenceError) || referenceError.Retries != 2 {
		t.Fatalf("Sign = %x, %v; want PIN error with two retries", signature, err)
	}

	if raw.verifies != 1 || raw.signatures != 0 || raw.closeCalls != 0 {
		t.Errorf("after wrong PIN: verifies/signatures/closes = %d/%d/%d", raw.verifies, raw.signatures, raw.closeCalls)
	}
}

func TestRSASignatureSchemes(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts crypto.SignerOpts
	}{
		{name: "PKCS1v15", opts: crypto.SHA256},
		{name: "PSS auto", opts: &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthAuto}},
		{name: "PSS equals hash", opts: &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash}},
		{name: "PSS exact", opts: &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: 8}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, raw := newRSASigningPeer(t)
			digest := sha256.Sum256([]byte("RSA host encoding"))
			original := bytes.Clone(digest[:])

			signature, err := key.Sign(t.Context(), rand.Reader, digest[:], tc.opts, nil)
			if err != nil {
				t.Fatal(err)
			}

			if options, ok := tc.opts.(*rsa.PSSOptions); ok {
				if err := rsa.VerifyPSS(&raw.rsa.PublicKey, crypto.SHA256, digest[:], signature, options); err != nil {
					t.Fatal(err)
				}
			} else if err := rsa.VerifyPKCS1v15(&raw.rsa.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(digest[:], original) || len(raw.inputs[0]) != raw.rsa.Size() || raw.verifies != 0 {
				t.Error("signing changed digest, sent a partial RSA block, or verified a missing PIN")
			}
		})
	}
}

func TestPSSAutoRejectsDifferentValidSaltLength(t *testing.T) {
	key, raw := newRSASigningPeer(t)
	digest := sha256.Sum256([]byte("exact Auto salt contract"))
	raw.response = func([]byte) iso7816.Response {
		signature, err := rsa.SignPSS(rand.Reader, raw.rsa, crypto.SHA256, digest[:], &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: 8})
		if err != nil {
			t.Fatal(err)
		}

		return signatureResponse(signature)
	}

	signature, err := key.Sign(t.Context(), rand.Reader, digest[:], &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthAuto}, nil)
	if signature != nil || !errors.Is(err, protocol.ErrInvalidResponse) {
		t.Fatalf("Sign = %x, %v; must reject valid signature with wrong Auto salt length", signature, err)
	}
}

type otherSigningOptions struct{}

func (otherSigningOptions) HashFunc() crypto.Hash { return crypto.SHA256 }

func TestInvalidSigningInputsDoNotPromptOrTransmit(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts crypto.SignerOpts
		size int
	}{
		{name: "unhashed message", opts: crypto.Hash(0), size: 32},
		{name: "unknown hash", opts: crypto.Hash(255), size: 32},
		{name: "short digest", opts: crypto.SHA256, size: 31},
		{name: "other options", opts: otherSigningOptions{}, size: 32},
		{name: "PSS on ECDSA", opts: &rsa.PSSOptions{Hash: crypto.SHA256}, size: 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, raw := newECDSASigningPeer(t, elliptic.P256(), protocol.DigitalSignature)
			prompts := 0
			pin := func(context.Context) (string, error) { prompts++; return "123456", nil }

			if _, err := key.Sign(t.Context(), rand.Reader, make([]byte, tc.size), tc.opts, PINAuthentication(protocol.ApplicationPIN, pin)); err == nil {
				t.Fatal("invalid signing input was accepted")
			}

			if prompts != 0 || len(raw.instructions) != 0 {
				t.Error("invalid signing input prompted or transmitted")
			}
		})
	}
}

func TestInvalidPSSOptionsDoNotPromptOrTransmit(t *testing.T) {
	for _, saltLength := range []int{-2, 1000} {
		t.Run(fmt.Sprintf("salt %d", saltLength), func(t *testing.T) {
			key, raw := newRSASigningPeer(t)
			digest := sha256.Sum256([]byte("invalid salt"))
			prompts := 0
			pin := func(context.Context) (string, error) { prompts++; return "123456", nil }

			if _, err := key.Sign(t.Context(), rand.Reader, digest[:], &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: saltLength}, PINAuthentication(protocol.ApplicationPIN, pin)); err == nil {
				t.Fatal("invalid salt length was accepted")
			}

			if prompts != 0 || len(raw.instructions) != 0 {
				t.Error("invalid salt length prompted or transmitted")
			}
		})
	}
}

func TestPINAuthenticationCanQueryCardBeforeGate(t *testing.T) {
	digest := sha256.Sum256([]byte("prompt can query card"))

	synctest.Test(t, func(t *testing.T) {
		key, raw := newECDSASigningPeer(t, elliptic.P256(), protocol.DigitalSignature)
		pin := func(ctx context.Context) (string, error) {
			ctx, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()

			if _, err := key.device.ReferenceStatus(ctx, protocol.ApplicationPIN); err != nil {
				return "", err
			}

			return "123456", nil
		}

		if _, err := key.Sign(t.Context(), rand.Reader, digest[:], crypto.SHA256, PINAuthentication(protocol.ApplicationPIN, pin)); err != nil {
			t.Fatal(err)
		}

		if raw.statuses != 1 || raw.verifies != 1 || raw.signatures != 1 {
			t.Errorf("status/VERIFY/signature counts = %d/%d/%d", raw.statuses, raw.verifies, raw.signatures)
		}
	})
}

func TestSigningRejectsBadResponsesAndStaleBinding(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response func([]byte) iso7816.Response
		stale    bool
	}{
		{name: "empty template", response: func([]byte) iso7816.Response { return iso7816.Response{Status: 0x9000} }},
		{name: "malformed DER", response: func([]byte) iso7816.Response { return signatureResponse([]byte{0x30, 0}) }},
		{name: "tampered signature", response: func(sig []byte) iso7816.Response { sig[len(sig)-1] ^= 1; return signatureResponse(sig) }},
		{
			name: "unexpected field", response: func(signature []byte) iso7816.Response {
				inner := append(signatureTLV(0x82, signature), 0x81, 0)
				return iso7816.Response{Status: 0x9000, Data: signatureTLV(0x7c, inner)}
			},
		},
		{name: "slot key replaced", stale: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, raw := newECDSASigningPeer(t, elliptic.P256(), protocol.DigitalSignature)
			digest := sha256.Sum256([]byte("untrusted response"))

			raw.response = tc.response
			if tc.stale {
				raw.ec = signingECDSA(t, elliptic.P256())
			}

			signature, err := key.Sign(t.Context(), rand.Reader, digest[:], crypto.SHA256, nil)
			if signature != nil || !errors.Is(err, protocol.ErrInvalidResponse) {
				t.Fatalf("Sign = %x, %v; want invalid response without signature", signature, err)
			}

			if raw.closeCalls != 0 {
				t.Error("complete but invalid signature closed a usable connection")
			}
		})
	}
}

func TestAuthenticationAndSignatureExcludeVendorExchange(t *testing.T) {
	digest := sha256.Sum256([]byte("atomic Global PIN/sign"))

	synctest.Test(t, func(t *testing.T) {
		key, raw := newECDSASigningPeer(t, elliptic.P256(), protocol.DigitalSignature)
		raw.authenticationReference = protocol.GlobalPIN
		verified, proceed := make(chan struct{}), make(chan struct{})

		release := sync.OnceFunc(func() { close(proceed) })
		defer release()

		raw.afterVerify = func() { close(verified); <-proceed }
		signed := make(chan error, 1)

		go func() {
			_, err := key.Sign(t.Context(), rand.Reader, digest[:], crypto.SHA256, PINAuthentication(protocol.GlobalPIN, signingPIN))
			signed <- err
		}()

		receive(t, verified, "PIN verification did not start")

		vendor := make(chan error, 1)

		go func() { _, err := key.device.Exchange(t.Context(), iso7816.Command{INS: 0xfd}); vendor <- err }()

		synctest.Wait()

		if len(raw.instructions) != 1 {
			t.Fatalf("instructions before signature = %x, want VERIFY only", raw.instructions)
		}

		release()

		if err := receive(t, signed, "signing did not finish"); err != nil {
			t.Fatal(err)
		}

		if err := receive(t, vendor, "vendor command did not finish"); err != nil {
			t.Fatal(err)
		}

		if want := []byte{0x20, 0x87, 0xfd}; !bytes.Equal(raw.instructions, want) {
			t.Errorf("instruction order = %x, want %x", raw.instructions, want)
		}
	})
}

func TestSigningPreservesCompletedResultAfterCancellation(t *testing.T) {
	key, raw := newECDSASigningPeer(t, elliptic.P256(), protocol.DigitalSignature)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	raw.afterSignature = cancel
	digest := sha256.Sum256([]byte("completed signature"))

	signature, err := key.Sign(ctx, rand.Reader, digest[:], crypto.SHA256, nil)
	if err != nil || !ecdsa.VerifyASN1(&raw.ec.PublicKey, digest[:], signature) {
		t.Fatalf("completed Sign = %x, %v", signature, err)
	}

	if raw.closeCalls != 0 {
		t.Error("late cancellation invalidated a completed signature")
	}
}

func TestCloseInterruptsSigningIO(t *testing.T) {
	digest := sha256.Sum256([]byte("close signing I/O"))

	synctest.Test(t, func(t *testing.T) {
		key, raw := newECDSASigningPeer(t, elliptic.P256(), protocol.DigitalSignature)
		started := make(chan struct{})
		raw.beforeSign = func(ctx context.Context) error {
			close(started)

			select {
			case <-raw.closed:
				return &transport.DeviceInvalidatedError{Err: io.ErrClosedPipe}
			case <-ctx.Done():
				return &transport.DeviceInvalidatedError{Err: ctx.Err()}
			}
		}
		finished := make(chan error, 1)

		go func() { _, err := key.Sign(t.Context(), rand.Reader, digest[:], crypto.SHA256, nil); finished <- err }()

		receive(t, started, "signing I/O did not start")

		if err := key.device.Close(); err != nil {
			t.Fatal(err)
		}

		err := receive(t, finished, "signing I/O did not stop after Close")

		var invalidated *transport.DeviceInvalidatedError
		if !errors.Is(err, io.ErrClosedPipe) || !errors.As(err, &invalidated) || raw.closeCalls != 1 {
			t.Fatalf("Sign after Close = %v, closes=%d", err, raw.closeCalls)
		}
	})
}
