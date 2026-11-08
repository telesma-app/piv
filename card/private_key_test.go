package card

import (
	"crypto"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"
	"testing"

	"github.com/telesma-app/piv/protocol"
)

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
