package card

import (
	"bytes"
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/telesma-app/piv/protocol"
)

func TestSignerUsesBoundContextAndPromptsEachCall(t *testing.T) {
	key, raw := newECDSASigningPeer(t, elliptic.P256(), 0x9c)
	raw.authenticationReference = protocol.GlobalPIN

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	prompts := 0
	pin := func(received context.Context) (string, error) {
		if received != ctx {
			t.Error("PIN callback received a substituted context")
		}

		prompts++

		return "123456", nil
	}
	adapter := key.Signer(ctx, PINAuthentication(protocol.GlobalPIN, pin))
	digest := sha256.Sum256([]byte("adapter context"))

	for range 2 {
		if _, err := adapter.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
			t.Fatal(err)
		}
	}

	cancel()

	if _, err := adapter.Sign(rand.Reader, digest[:], crypto.SHA256); !errors.Is(err, context.Canceled) {
		t.Fatalf("Sign with canceled bound context = %v", err)
	}

	if prompts != 2 || raw.verifies != 2 || raw.signatures != 2 {
		t.Errorf("prompts/VERIFY/signature counts = %d/%d/%d", prompts, raw.verifies, raw.signatures)
	}
}

func TestPINAuthenticationFailureDoesNotReachCard(t *testing.T) {
	key, raw := newECDSASigningPeer(t, elliptic.P256(), 0x9c)
	cause := errors.New("PIN prompt canceled")
	pin := func(context.Context) (string, error) { return "", cause }
	digest := sha256.Sum256([]byte("PIN source failure"))

	_, err := key.Signer(t.Context(), PINAuthentication(protocol.ApplicationPIN, pin)).Sign(rand.Reader, digest[:], crypto.SHA256)
	if !errors.Is(err, cause) || len(raw.instructions) != 0 {
		t.Fatalf("Sign after PIN source failure = %v, instructions=%x", err, raw.instructions)
	}
}

func TestAuthenticationSourceFailureDoesNotReachCard(t *testing.T) {
	key, raw := newECDSASigningPeer(t, elliptic.P256(), protocol.DigitalSignature)
	cause := errors.New("biometric acquisition canceled")
	data := []byte{0x10, 0x80, 0xff}
	authentication := func(ctx context.Context) (protocol.VerifyRequest, error) {
		if ctx != t.Context() {
			t.Error("authentication source received a substituted context")
		}

		return protocol.VerifyRequest{Reference: protocol.PrimaryFingerOCC, Data: data}, cause
	}
	digest := sha256.Sum256([]byte("authentication source failure"))

	_, err := key.Signer(t.Context(), authentication).Sign(rand.Reader, digest[:], crypto.SHA256)
	if !errors.Is(err, cause) || len(raw.instructions) != 0 {
		t.Fatalf("Sign after authentication source failure = %v, instructions=%x", err, raw.instructions)
	}

	if !bytes.Equal(data, []byte{0x10, 0x80, 0xff}) {
		t.Error("Sign cleared source-owned data after an acquisition error")
	}
}
