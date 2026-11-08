package card

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
	"testing"

	"github.com/telesma-app/piv/protocol"
)

func TestPrivateKeyBindingDoesNotPerformIOOrCopyPublicKey(t *testing.T) {
	for _, bits := range []int{1024, 2048, 3072, 4096} {
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

func TestPrivateKeyBindsEllipticCurvesWithoutIOOrCopy(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			device, raw := newDevice(t)
			public := &signingECDSA(t, curve).PublicKey

			key, err := device.PrivateKey(protocol.DigitalSignature, public)
			if err != nil {
				t.Fatal(err)
			}

			if key.Public() != public || raw.calls != 0 {
				t.Error("binding copied the public key or performed I/O")
			}
		})
	}
}

func TestPrivateKeyBindsEd25519WithoutIOOrCopy(t *testing.T) {
	device, raw := newDevice(t)
	public := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)

	key, err := device.PrivateKey(protocol.DigitalSignature, public)
	if err != nil {
		t.Fatal(err)
	}

	if returned := key.Public().(ed25519.PublicKey); &returned[0] != &public[0] || raw.calls != 0 {
		t.Error("binding copied the public key or performed I/O")
	}
}

func TestPrivateKeyBindsX25519WithoutIOOrCopy(t *testing.T) {
	device, raw := newDevice(t)

	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	public := private.PublicKey()

	key, err := device.PrivateKey(protocol.KeyManagement, public)
	if err != nil {
		t.Fatal(err)
	}

	if key.Public() != public || raw.calls != 0 {
		t.Error("binding copied the public key or performed I/O")
	}
}

func TestPrivateKeyRejectsUnsupportedAlgorithmsWithoutIO(t *testing.T) {
	private, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, publicKey := range []crypto.PublicKey{
		private.PublicKey(),
		&rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2048), E: 65537},
	} {
		device, _ := newDevice(t)
		if _, err := device.PrivateKey(protocol.DigitalSignature, publicKey); err == nil {
			t.Fatalf("accepted unsupported key type %T", publicKey)
		}
	}
}
