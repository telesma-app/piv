package card

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/client"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

func TestEd25519SignRFC8032Vectors(t *testing.T) {
	decode := func(value string) []byte {
		t.Helper()

		data, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}

		return data
	}

	// RFC 8032, Section 7.1, TEST 1 and TEST 2.
	for _, tc := range []struct {
		name      string
		seed      string
		message   []byte
		signature string
		opts      crypto.SignerOpts
	}{
		{
			name: "nil message", seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
			signature: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
				"5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
			opts: crypto.Hash(0),
		},
		{
			name: "empty message", seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
			message: []byte{},
			signature: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
				"5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
			opts: &ed25519.Options{},
		},
		{
			name: "one byte", seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
			message: []byte{0x72},
			signature: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
				"085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
			opts: crypto.Hash(0),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			private := ed25519.NewKeyFromSeed(decode(tc.seed))
			key, raw := newEd25519SigningPeer(t, private)

			signature, err := key.Sign(t.Context(), nil, tc.message, tc.opts, nil)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(signature, decode(tc.signature)) {
				t.Errorf("Ed25519 signature = %x, want %s", signature, tc.signature)
			}

			if len(raw.inputs) != 1 || raw.inputs[0] == nil || !bytes.Equal(raw.inputs[0], tc.message) {
				t.Errorf("Ed25519 input = %x; want the original, present message %x", raw.inputs, tc.message)
			}
		})
	}
}

func TestEd25519SignerPreservesLongMessage(t *testing.T) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	key, raw := newEd25519SigningPeer(t, private)
	message := bytes.Repeat([]byte("PIV Ed25519 message without host hashing"), 100)
	original := bytes.Clone(message)

	signature, err := key.Signer(t.Context(), PINAuthentication(protocol.ApplicationPIN, signingPIN)).Sign(nil, message, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}

	if !ed25519.Verify(private.Public().(ed25519.PublicKey), original, signature) {
		t.Error("signature does not verify against the original message")
	}

	if !bytes.Equal(message, original) || len(raw.inputs) != 1 || !bytes.Equal(raw.inputs[0], original) {
		t.Error("signing changed or hashed the borrowed message")
	}

	if raw.verifies != 1 || raw.signatures != 1 {
		t.Errorf("VERIFY/signature counts = %d/%d, want 1/1", raw.verifies, raw.signatures)
	}
}

func TestEd25519RejectsUnsupportedOptionsBeforeAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts crypto.SignerOpts
	}{
		{name: "prehashed", opts: crypto.SHA512},
		{name: "Ed25519ph", opts: &ed25519.Options{Hash: crypto.SHA512}},
		{name: "Ed25519ctx", opts: &ed25519.Options{Context: "PIV"}},
		{name: "RSA-PSS", opts: &rsa.PSSOptions{Hash: crypto.SHA512}},
		{name: "other options", opts: otherSigningOptions{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, raw := newEd25519SigningPeer(t, ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
			prompts := 0
			authentication := func(context.Context) (protocol.VerifyRequest, error) {
				prompts++
				return protocol.VerifyRequest{Reference: protocol.ApplicationPIN}, nil
			}

			if _, err := key.Sign(t.Context(), nil, []byte("message"), tc.opts, authentication); err == nil {
				t.Fatal("unsupported Ed25519 options accepted")
			}

			if prompts != 0 || len(raw.instructions) != 0 {
				t.Error("unsupported options prompted or performed I/O")
			}
		})
	}
}

func TestEd25519RejectsInvalidResponsesAndStaleBinding(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response func([]byte) iso7816.Response
		stale    bool
	}{
		{name: "empty signature", response: func([]byte) iso7816.Response { return signatureResponse([]byte{}) }},
		{name: "short signature", response: func(sig []byte) iso7816.Response { return signatureResponse(sig[:63]) }},
		{name: "tampered signature", response: func(sig []byte) iso7816.Response { sig[0] ^= 1; return signatureResponse(sig) }},
		{name: "slot key replaced", stale: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, raw := newEd25519SigningPeer(t, ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))

			raw.response = tc.response
			if tc.stale {
				raw.ed = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
			}

			signature, err := key.Sign(t.Context(), nil, []byte("untrusted Ed25519 response"), crypto.Hash(0), nil)
			if signature != nil || !errors.Is(err, protocol.ErrInvalidResponse) {
				t.Fatalf("Sign = %x, %v; want invalid response without signature", signature, err)
			}

			if raw.closeCalls != 0 {
				t.Error("invalid signature closed a usable connection")
			}
		})
	}
}

func TestX25519CannotSignBeforeAuthentication(t *testing.T) {
	device, raw := newDevice(t)

	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	key, err := device.PrivateKey(protocol.KeyManagement, private.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	prompts := 0
	authentication := func(context.Context) (protocol.VerifyRequest, error) {
		prompts++
		return protocol.VerifyRequest{}, nil
	}

	if _, err := key.Sign(t.Context(), nil, []byte("message"), crypto.Hash(0), authentication); err == nil {
		t.Fatal("X25519 signing accepted")
	}

	if prompts != 0 || raw.calls != 0 {
		t.Error("X25519 signing prompted or performed I/O")
	}
}

func TestP521SigningPreservesDigestLengthAndLeadingZeros(t *testing.T) {
	for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA512} {
		t.Run(hash.String(), func(t *testing.T) {
			key, raw := newECDSASigningPeer(t, elliptic.P521(), protocol.DigitalSignature)
			digest := make([]byte, hash.Size())
			digest[1], digest[len(digest)-1] = 0x80, 0x42
			original := bytes.Clone(digest)

			signature, err := key.Sign(t.Context(), nil, digest, hash, nil)
			if err != nil {
				t.Fatal(err)
			}

			if !ecdsa.VerifyASN1(&raw.ec.PublicKey, original, signature) {
				t.Error("P-521 signature does not verify against the original digest")
			}

			if !bytes.Equal(digest, original) || len(raw.inputs) != 1 || !bytes.Equal(raw.inputs[0], original) {
				t.Errorf("P-521 wire input = %x, want original digest %x", raw.inputs, original)
			}
		})
	}
}

func TestRSA4096SignatureSchemes(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts crypto.SignerOpts
	}{
		{name: "PKCS1v15", opts: crypto.SHA512},
		{name: "PSS", opts: &rsa.PSSOptions{Hash: crypto.SHA512, SaltLength: rsa.PSSSaltLengthEqualsHash}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, raw := newRSASigningPeer(t)
			raw.rsa, raw.algorithm = signingRSA4096(t), protocol.RSA4096

			var err error

			key, err = key.device.PrivateKey(protocol.DigitalSignature, &raw.rsa.PublicKey)
			if err != nil {
				t.Fatal(err)
			}

			digest := sha512.Sum512([]byte("RSA-4096 host encoding"))

			signature, err := key.Sign(t.Context(), rand.Reader, digest[:], tc.opts, nil)
			if err != nil {
				t.Fatal(err)
			}

			if opts, ok := tc.opts.(*rsa.PSSOptions); ok {
				err = rsa.VerifyPSS(&raw.rsa.PublicKey, crypto.SHA512, digest[:], signature, opts)
			} else {
				err = rsa.VerifyPKCS1v15(&raw.rsa.PublicKey, crypto.SHA512, digest[:], signature)
			}

			if err != nil {
				t.Fatal(err)
			}

			if len(signature) != 512 || len(raw.inputs) != 1 || len(raw.inputs[0]) != 512 {
				t.Error("RSA-4096 signing did not use a complete 512-byte block")
			}
		})
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

func TestNilAuthenticationSkipsVerify(t *testing.T) {
	key, raw := newECDSASigningPeer(t, elliptic.P256(), protocol.CardAuthentication)
	digest := sha256.Sum256([]byte("PIN never key"))

	if _, err := key.Sign(t.Context(), rand.Reader, digest[:], crypto.SHA256, nil); err != nil {
		t.Fatal(err)
	}

	if raw.verifies != 0 || raw.signatures != 1 || len(raw.instructions) != 1 {
		t.Errorf("without authentication: VERIFY/signature/instruction counts = %d/%d/%d, want 0/1/1", raw.verifies, raw.signatures, len(raw.instructions))
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

func TestSigningInvalidationClosesSession(t *testing.T) {
	for _, phase := range []string{"VERIFY", "GENERAL AUTHENTICATE"} {
		t.Run(phase, func(t *testing.T) {
			private := signingECDSA(t, elliptic.P256())
			digest := sha256.Sum256([]byte("invalidated signing session"))
			cause := errors.New("card removed")
			closeErr := errors.New("disconnect failed")
			invalidated := &transport.DeviceInvalidatedError{Err: cause}

			steps := []exchangeStep{{
				command: []byte{0, 0x20, 0, 0x80, 8, '1', '2', '3', '4', '5', '6', 0xff, 0xff}, err: invalidated,
			}}
			if phase == "GENERAL AUTHENTICATE" {
				steps[0].err = nil
				steps[0].response = iso7816.Response{Status: 0x9000}

				command := append([]byte{0, 0x87, 0x11, 0x9c, 38, 0x7c, 36, 0x82, 0, 0x81, 32}, digest[:]...)
				steps = append(steps, exchangeStep{command: append(command, 0), err: invalidated})
			}

			device, raw := newDevice(t, steps...)
			raw.closeErr = closeErr

			key, err := device.PrivateKey(protocol.DigitalSignature, &private.PublicKey)
			if err != nil {
				t.Fatal(err)
			}

			authentication := PINAuthentication(protocol.ApplicationPIN, signingPIN)

			signature, err := key.Sign(t.Context(), rand.Reader, digest[:], crypto.SHA256, authentication)

			var got *transport.DeviceInvalidatedError
			if signature != nil || !errors.As(err, &got) || got != invalidated || !errors.Is(err, cause) || !errors.Is(err, closeErr) {
				t.Errorf("Sign = %x, %v; want no signature, original invalidation and close error", signature, err)
			}

			if raw.calls != len(steps) || raw.closeCalls != 1 {
				t.Errorf("after invalidation: exchanges=%d closes=%d, want %d and 1", raw.calls, raw.closeCalls, len(steps))
			}

			signature, err = key.Sign(t.Context(), rand.Reader, digest[:], crypto.SHA256, authentication)
			if signature != nil || !errors.Is(err, io.ErrClosedPipe) {
				t.Errorf("Sign after invalidation = %x, %v; want closed pipe", signature, err)
			}

			if err := device.Close(); !errors.Is(err, closeErr) || raw.calls != len(steps) || raw.closeCalls != 1 {
				t.Errorf("Close after invalidation = %v; exchanges=%d closes=%d, want %d and 1", err, raw.calls, raw.closeCalls, len(steps))
			}
		})
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
