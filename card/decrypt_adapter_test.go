package card

import (
	"bytes"
	"context"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/telesma-app/piv/protocol"
)

func TestDecrypterUsesExplicitContextAndAuthentication(t *testing.T) {
	key, raw := newRSADecryptionPeer(t)
	raw.authenticationReference = protocol.GlobalPIN

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	prompts := 0
	authentication := PINAuthentication(protocol.GlobalPIN, func(received context.Context) (string, error) {
		if received != ctx {
			t.Error("Decrypter substituted its context")
		}

		prompts++

		return "123456", nil
	})

	adapter := key.Decrypter(ctx, authentication)
	if adapter.Public() != key.Public() {
		t.Fatal("Decrypter.Public replaced the borrowed public key")
	}

	message := bytes.Repeat([]byte{0xa5}, 16)
	ciphertext := rsaCiphertext(t, &raw.rsa.PublicKey, message, nil)

	opts := &rsa.PKCS1v15DecryptOptions{SessionKeyLen: 16} //nolint:staticcheck // Legacy PIV compatibility requires PKCS#1 v1.5 support.
	for range 2 {
		plaintext, err := adapter.Decrypt(bytes.NewReader(make([]byte, 16)), ciphertext, opts)
		if err != nil || !bytes.Equal(plaintext, message) {
			t.Fatalf("Decrypter.Decrypt = %x, %v", plaintext, err)
		}
	}

	cancel()

	if _, err := adapter.Decrypt(bytes.NewReader(make([]byte, 16)), ciphertext, opts); !errors.Is(err, context.Canceled) {
		t.Fatalf("Decrypt with canceled adapter context = %v", err)
	}

	if prompts != 2 || raw.verifies != 2 || raw.signatures != 2 {
		t.Fatalf("source/VERIFY/GA counts = %d/%d/%d", prompts, raw.verifies, raw.signatures)
	}
}
