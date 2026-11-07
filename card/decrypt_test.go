package card

import (
	"bytes"
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"math/big"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/client"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

func newRSADecryptionPeer(t testing.TB) (*PrivateKey, *signaturePeer) {
	t.Helper()
	private := signingRSA(t)
	raw := &signaturePeer{
		t: t, reference: protocol.KeyManagement, algorithm: protocol.RSA2048,
		rsa: private, closed: make(chan struct{}),
		authenticationReference: protocol.ApplicationPIN,
		authenticationData:      []byte{'1', '2', '3', '4', '5', '6', 0xff, 0xff},
	}
	device := New(raw)

	t.Cleanup(func() { _ = device.Close() })

	key, err := device.PrivateKey(protocol.KeyManagement, &private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	return key, raw
}

func rsaCiphertext(t testing.TB, publicKey *rsa.PublicKey, message []byte, opts crypto.DecrypterOpts) []byte {
	t.Helper()

	var ciphertext []byte

	var err error

	if oaep, ok := opts.(*rsa.OAEPOptions); ok {
		ciphertext, err = rsa.EncryptOAEP(oaep.Hash.New(), rand.Reader, publicKey, message, oaep.Label)
	} else {
		ciphertext, err = rsa.EncryptPKCS1v15(rand.Reader, publicKey, message) //nolint:staticcheck // Legacy PIV compatibility requires PKCS#1 v1.5 support.
	}

	if err != nil {
		t.Fatal(err)
	}

	return ciphertext
}

func TestRSADecryptOAEPWithStandardEncryption(t *testing.T) {
	for _, hash := range []crypto.Hash{
		crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512,
		crypto.SHA512_224, crypto.SHA512_256,
		crypto.SHA3_224, crypto.SHA3_256, crypto.SHA3_384, crypto.SHA3_512,
	} {
		t.Run(hash.String(), func(t *testing.T) {
			key, raw := newRSADecryptionPeer(t)
			opts := &rsa.OAEPOptions{Hash: hash, Label: []byte("PIV confidential key transport")}
			message := []byte("a symmetric key from another participant")
			ciphertext := rsaCiphertext(t, &raw.rsa.PublicKey, message, opts)
			originalCiphertext := bytes.Clone(ciphertext)
			originalLabel := bytes.Clone(opts.Label)

			var encoded []byte

			raw.response = func(em []byte) iso7816.Response {
				response := signatureResponse(em)

				parsed, err := protocol.ParseDynamicAuthentication(response.Data)
				if err != nil {
					t.Fatal(err)
				}

				encoded = parsed.Response

				return response
			}

			plaintext, err := key.Decrypt(t.Context(), nil, ciphertext, opts, nil)
			if err != nil || !bytes.Equal(plaintext, message) {
				t.Fatalf("Decrypt = %x, %v", plaintext, err)
			}

			if !bytes.Equal(ciphertext, originalCiphertext) || !bytes.Equal(opts.Label, originalLabel) || opts.Hash != hash || opts.MGFHash != 0 {
				t.Fatal("Decrypt modified borrowed ciphertext or OAEP options")
			}

			if !bytes.Equal(encoded, make([]byte, len(encoded))) {
				t.Fatal("Decrypt retained the secret encoded message")
			}

			if raw.verifies != 0 || raw.signatures != 1 || !bytes.Equal(raw.inputs[0], ciphertext) {
				t.Fatalf("VERIFY/GA/input = %d/%d/%x", raw.verifies, raw.signatures, raw.inputs)
			}
		})
	}
}

func TestRSADecryptPKCS1v15Modes(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts crypto.DecrypterOpts
	}{
		{name: "nil options"},
		{name: "explicit PKCS1v15", opts: &rsa.PKCS1v15DecryptOptions{}},                  //nolint:staticcheck // Legacy PIV compatibility requires PKCS#1 v1.5 support.
		{name: "fixed session key", opts: &rsa.PKCS1v15DecryptOptions{SessionKeyLen: 16}}, //nolint:staticcheck // Legacy PIV compatibility requires PKCS#1 v1.5 support.
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, raw := newRSADecryptionPeer(t)
			message := bytes.Repeat([]byte{0xa5}, 16)
			ciphertext := rsaCiphertext(t, &raw.rsa.PublicKey, message, tc.opts)
			random := bytes.NewReader(bytes.Repeat([]byte{0x42}, 16))

			plaintext, err := key.Decrypt(t.Context(), random, ciphertext, tc.opts, PINAuthentication(protocol.ApplicationPIN, signingPIN))
			if err != nil || !bytes.Equal(plaintext, message) {
				t.Fatalf("Decrypt = %x, %v", plaintext, err)
			}

			if raw.verifies != 1 || raw.signatures != 1 {
				t.Errorf("VERIFY/GA = %d/%d", raw.verifies, raw.signatures)
			}

			if opts, ok := tc.opts.(*rsa.PKCS1v15DecryptOptions); ok && opts.SessionKeyLen > 0 { //nolint:staticcheck // Legacy PIV compatibility requires PKCS#1 v1.5 support.
				if random.Len() != 0 || opts.SessionKeyLen != 16 {
					t.Fatal("session-key random was not consumed or caller options changed")
				}
			} else if random.Len() != 16 {
				t.Fatal("ordinary decryption consumed random bytes")
			}
		})
	}
}

func TestRSADecryptSessionKeyFallback(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
		edit func([]byte)
	}{
		{name: "invalid header", size: 16, edit: func(em []byte) { em[0] = 1 }},
		{name: "invalid block type", size: 16, edit: func(em []byte) { em[1] = 1 }},
		{name: "short padding", size: 16, edit: func(em []byte) { em[9] = 0 }},
		{name: "missing separator", size: 16, edit: func(em []byte) { em[len(em)-17] = 0x42 }},
		{name: "short plaintext", size: 17, edit: func([]byte) {}},
		{name: "long plaintext", size: 15, edit: func([]byte) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, raw := newRSADecryptionPeer(t)
			message := bytes.Repeat([]byte{0xa5}, 16)
			ciphertext := rsaCiphertext(t, &raw.rsa.PublicKey, message, nil)
			raw.response = func(em []byte) iso7816.Response { tc.edit(em); return signatureResponse(em) }
			fallback := bytes.Repeat([]byte{0x42}, tc.size)
			opts := &rsa.PKCS1v15DecryptOptions{SessionKeyLen: tc.size} //nolint:staticcheck // Legacy PIV compatibility requires PKCS#1 v1.5 support.

			plaintext, err := key.Decrypt(t.Context(), bytes.NewReader(fallback), ciphertext, opts, nil)
			if err != nil || !bytes.Equal(plaintext, fallback) {
				t.Fatalf("Decrypt = %x, %v; want random fallback %x without error", plaintext, err, fallback)
			}
		})
	}
}

func TestRSADecryptRejectsInvalidInputBeforeAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name       string
		opts       crypto.DecrypterOpts
		ciphertext func(*rsa.PublicKey) []byte
	}{
		{name: "unknown options", opts: 42},
		{name: "zero OAEP hash", opts: &rsa.OAEPOptions{}},
		{name: "unknown OAEP hash", opts: &rsa.OAEPOptions{Hash: crypto.Hash(255)}},
		{name: "unsupported OAEP hash", opts: &rsa.OAEPOptions{Hash: crypto.MD5}},
		{name: "unknown MGF hash", opts: &rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.Hash(255)}},
		{name: "negative session key length", opts: &rsa.PKCS1v15DecryptOptions{SessionKeyLen: -1}}, //nolint:staticcheck // Legacy PIV compatibility requires PKCS#1 v1.5 support.
		{name: "session key does not fit", opts: &rsa.PKCS1v15DecryptOptions{SessionKeyLen: 246}},   //nolint:staticcheck // Legacy PIV compatibility requires PKCS#1 v1.5 support.
		{name: "short ciphertext", ciphertext: func(key *rsa.PublicKey) []byte { return make([]byte, key.Size()-1) }},
		{name: "long ciphertext", ciphertext: func(key *rsa.PublicKey) []byte { return make([]byte, key.Size()+1) }},
		{name: "ciphertext equals modulus", ciphertext: func(key *rsa.PublicKey) []byte { return key.N.Bytes() }},
		{
			name: "ciphertext greater than modulus",
			ciphertext: func(key *rsa.PublicKey) []byte {
				return new(big.Int).Add(key.N, big.NewInt(1)).Bytes()
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, raw := newRSADecryptionPeer(t)

			ciphertext := make([]byte, raw.rsa.Size())
			if tc.ciphertext != nil {
				ciphertext = tc.ciphertext(&raw.rsa.PublicKey)
			}

			sourced := 0
			authentication := func(context.Context) (protocol.VerifyRequest, error) {
				sourced++
				return protocol.VerifyRequest{}, nil
			}

			plaintext, err := key.Decrypt(t.Context(), rand.Reader, ciphertext, tc.opts, authentication)
			if err == nil || plaintext != nil || sourced != 0 || len(raw.instructions) != 0 {
				t.Fatalf("Decrypt = %x, %v; source calls=%d, instructions=%x", plaintext, err, sourced, raw.instructions)
			}
		})
	}

	key, raw := newECDSASigningPeer(t, elliptic.P256(), protocol.KeyManagement)
	if plaintext, err := key.Decrypt(t.Context(), nil, make([]byte, 256), nil, nil); err == nil || plaintext != nil || len(raw.instructions) != 0 {
		t.Fatalf("Decrypt with an ECC binding = %x, %v, instructions=%x", plaintext, err, raw.instructions)
	}
}

func TestRSADecryptRandomFailurePrecedesAuthentication(t *testing.T) {
	key, raw := newRSADecryptionPeer(t)
	opts := &rsa.PKCS1v15DecryptOptions{SessionKeyLen: 16} //nolint:staticcheck // Legacy PIV compatibility requires PKCS#1 v1.5 support.
	ciphertext := make([]byte, raw.rsa.Size())
	sourced := false
	authentication := func(context.Context) (protocol.VerifyRequest, error) {
		sourced = true
		return protocol.VerifyRequest{}, nil
	}

	plaintext, err := key.Decrypt(t.Context(), bytes.NewReader([]byte{1}), ciphertext, opts, authentication)
	if !errors.Is(err, io.ErrUnexpectedEOF) || plaintext != nil || sourced || len(raw.instructions) != 0 {
		t.Fatalf("Decrypt = %x, %v; sourced=%t instructions=%x", plaintext, err, sourced, raw.instructions)
	}
}

func TestRSADecryptRejectsMalformedResponsesWithoutMaskingErrors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response func([]byte) iso7816.Response
		want     error
	}{
		{name: "missing response", response: func([]byte) iso7816.Response { return iso7816.Response{Status: 0x9000} }, want: protocol.ErrInvalidResponse},
		{name: "short response", response: func(em []byte) iso7816.Response { return signatureResponse(em[1:]) }, want: protocol.ErrInvalidResponse},
		{name: "long response", response: func(em []byte) iso7816.Response { return signatureResponse(append(em, 0)) }, want: protocol.ErrInvalidResponse},
		{
			name: "unexpected field", want: protocol.ErrInvalidResponse,
			response: func(em []byte) iso7816.Response {
				inner := append(signatureTLV(0x82, em), 0x81, 0)
				return iso7816.Response{Status: 0x9000, Data: signatureTLV(0x7c, inner)}
			},
		},
		{
			name: "APDU failure", want: &iso7816.APDUError{SW1: 0x69, SW2: 0x82},
			response: func([]byte) iso7816.Response { return iso7816.Response{Status: 0x6982} },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, raw := newRSADecryptionPeer(t)
			raw.response = tc.response
			ciphertext := rsaCiphertext(t, &raw.rsa.PublicKey, []byte("1234567890123456"), nil)
			plaintext, err := key.Decrypt(t.Context(), bytes.NewReader(make([]byte, 16)), ciphertext, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: 16}, nil) //nolint:staticcheck // Legacy PIV compatibility requires PKCS#1 v1.5 support.

			if plaintext != nil {
				t.Fatal("returned a fallback for malformed response or APDU failure")
			}

			if want, ok := tc.want.(*iso7816.APDUError); ok {
				var got *iso7816.APDUError
				if !errors.As(err, &got) || got.StatusWord() != want.StatusWord() {
					t.Fatalf("Decrypt = %v, want APDU %x", err, want.StatusWord())
				}
			} else if !errors.Is(err, tc.want) {
				t.Fatalf("Decrypt = %v, want %v", err, tc.want)
			}

			if raw.closeCalls != 0 {
				t.Fatal("a complete rejection invalidated the session")
			}
		})
	}
}

func TestRSADecryptPaddingErrorsAndEncodedMessageCleanup(t *testing.T) {
	for _, opts := range []crypto.DecrypterOpts{nil, &rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA256, Label: []byte("expected")}} {
		key, raw := newRSADecryptionPeer(t)
		ciphertext := rsaCiphertext(t, &raw.rsa.PublicKey, []byte("message"), opts)

		var encoded []byte

		raw.response = func(em []byte) iso7816.Response {
			em[0] = 1
			response := signatureResponse(em)

			parsed, err := protocol.ParseDynamicAuthentication(response.Data)
			if err != nil {
				t.Fatal(err)
			}

			encoded = parsed.Response

			return response
		}

		plaintext, err := key.Decrypt(t.Context(), nil, ciphertext, opts, nil)
		if plaintext != nil || err != rsa.ErrDecryption {
			t.Fatalf("Decrypt = %x, %v; want only padding error", plaintext, err)
		}

		if !bytes.Equal(encoded, make([]byte, len(encoded))) {
			t.Fatal("padding failure retained encoded-message storage")
		}
	}

	key, raw := newRSADecryptionPeer(t)
	opts := &rsa.OAEPOptions{Hash: crypto.SHA256, Label: []byte("expected")}
	ciphertext := rsaCiphertext(t, &raw.rsa.PublicKey, []byte("message"), opts)

	opts.Label = []byte("other")
	if plaintext, err := key.Decrypt(t.Context(), nil, ciphertext, opts, nil); plaintext != nil || err != rsa.ErrDecryption {
		t.Fatalf("Decrypt with wrong OAEP label = %x, %v", plaintext, err)
	}
}

func TestRSADecryptAuthenticationOwnership(t *testing.T) {
	for _, failed := range []bool{false, true} {
		key, raw := newRSADecryptionPeer(t)
		raw.authenticationReference = protocol.GlobalPIN
		ciphertext := rsaCiphertext(t, &raw.rsa.PublicKey, []byte("message"), nil)

		data := bytes.Clone(raw.authenticationData)
		if failed {
			data[0] = '0'
		}

		authentication := func(ctx context.Context) (protocol.VerifyRequest, error) {
			if _, err := key.device.ReferenceStatus(ctx, protocol.GlobalPIN); err != nil {
				return protocol.VerifyRequest{}, err
			}

			return protocol.VerifyRequest{Reference: protocol.GlobalPIN, Data: data}, nil
		}

		_, err := key.Decrypt(t.Context(), nil, ciphertext, nil, authentication)
		if failed {
			var referenceError *client.ReferenceDataError
			if !errors.As(err, &referenceError) || raw.signatures != 0 {
				t.Fatalf("Decrypt after wrong PIN = %v, GA calls=%d", err, raw.signatures)
			}
		} else if err != nil || raw.statuses != 1 || raw.verifies != 1 || raw.signatures != 1 {
			t.Fatalf("Decrypt = %v, status/VERIFY/GA=%d/%d/%d", err, raw.statuses, raw.verifies, raw.signatures)
		}

		if !bytes.Equal(data, make([]byte, len(data))) {
			t.Fatal("Decrypt did not clear owned authentication data")
		}
	}

	key, raw := newRSADecryptionPeer(t)
	data := []byte{1, 2, 3}
	cause := errors.New("authentication acquisition failed")
	authentication := func(context.Context) (protocol.VerifyRequest, error) {
		return protocol.VerifyRequest{Reference: protocol.PrimaryFingerOCC, Data: data}, cause
	}

	_, err := key.Decrypt(t.Context(), nil, make([]byte, raw.rsa.Size()), nil, authentication)
	if !errors.Is(err, cause) || !bytes.Equal(data, []byte{1, 2, 3}) || len(raw.instructions) != 0 {
		t.Fatalf("Decrypt after source failure = %v, source data=%x, instructions=%x", err, data, raw.instructions)
	}
}

func TestQueuedRSADecryptCancellationClearsAuthentication(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		key, raw := newRSADecryptionPeer(t)
		ciphertext := rsaCiphertext(t, &raw.rsa.PublicKey, []byte("message"), nil)
		started, proceed := make(chan struct{}), make(chan struct{})

		release := sync.OnceFunc(func() { close(proceed) })
		defer release()

		raw.beforeSign = func(context.Context) error { close(started); <-proceed; return nil }
		active := make(chan error, 1)

		go func() { _, err := key.Decrypt(t.Context(), nil, ciphertext, nil, nil); active <- err }()

		receive(t, started, "active decryption did not start")

		data := bytes.Clone(raw.authenticationData)
		sourced := make(chan struct{})
		authentication := func(context.Context) (protocol.VerifyRequest, error) {
			close(sourced)
			return protocol.VerifyRequest{Reference: protocol.ApplicationPIN, Data: data}, nil
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		queued := make(chan error, 1)

		go func() { _, err := key.Decrypt(ctx, nil, ciphertext, nil, authentication); queued <- err }()

		receive(t, sourced, "queued decryption did not obtain authentication")
		synctest.Wait()
		cancel()

		if err := receive(t, queued, "queued decryption ignored cancellation"); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}

		if !bytes.Equal(data, make([]byte, len(data))) || raw.verifies != 0 || raw.closeCalls != 0 {
			t.Fatal("queued cancellation retained authentication or changed the active session")
		}

		release()

		if err := receive(t, active, "active decryption did not finish"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRSADecryptAuthenticationExcludesVendorExchange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		key, raw := newRSADecryptionPeer(t)
		ciphertext := rsaCiphertext(t, &raw.rsa.PublicKey, []byte("message"), nil)
		verified, proceed := make(chan struct{}), make(chan struct{})

		release := sync.OnceFunc(func() { close(proceed) })
		defer release()

		raw.afterVerify = func() { close(verified); <-proceed }
		decrypted := make(chan error, 1)

		go func() {
			_, err := key.Decrypt(t.Context(), nil, ciphertext, nil, PINAuthentication(protocol.ApplicationPIN, signingPIN))
			decrypted <- err
		}()

		receive(t, verified, "VERIFY did not start")

		vendor := make(chan error, 1)

		go func() { _, err := key.device.Exchange(t.Context(), iso7816.Command{INS: 0xfd}); vendor <- err }()

		synctest.Wait()

		if len(raw.instructions) != 1 {
			t.Fatalf("instruction order before decryption = %x", raw.instructions)
		}

		release()

		if err := receive(t, decrypted, "decryption did not finish"); err != nil {
			t.Fatal(err)
		}

		if err := receive(t, vendor, "vendor exchange did not finish"); err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(raw.instructions, []byte{0x20, 0x87, 0xfd}) {
			t.Fatalf("instruction order = %x", raw.instructions)
		}
	})
}

func TestRSADecryptCompletedResultSurvivesCancellation(t *testing.T) {
	key, raw := newRSADecryptionPeer(t)
	message := []byte("completed decryption")
	ciphertext := rsaCiphertext(t, &raw.rsa.PublicKey, message, nil)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	raw.afterSignature = cancel

	plaintext, err := key.Decrypt(ctx, nil, ciphertext, nil, nil)
	if err != nil || !bytes.Equal(plaintext, message) || raw.closeCalls != 0 {
		t.Fatalf("completed Decrypt = %x, %v, closes=%d", plaintext, err, raw.closeCalls)
	}
}

func TestCloseInterruptsRSADecrypt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		key, raw := newRSADecryptionPeer(t)
		ciphertext := rsaCiphertext(t, &raw.rsa.PublicKey, []byte("message"), nil)
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

		go func() { _, err := key.Decrypt(t.Context(), nil, ciphertext, nil, nil); finished <- err }()

		receive(t, started, "decryption did not start")

		if err := key.device.Close(); err != nil {
			t.Fatal(err)
		}

		err := receive(t, finished, "decryption did not stop after Close")

		var invalidated *transport.DeviceInvalidatedError
		if !errors.As(err, &invalidated) || !errors.Is(err, io.ErrClosedPipe) || raw.closeCalls != 1 {
			t.Fatalf("Decrypt after Close = %v, closes=%d", err, raw.closeCalls)
		}
	})
}
