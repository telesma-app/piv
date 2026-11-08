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
	for _, tc := range []struct {
		bits      int
		algorithm protocol.Algorithm
	}{
		{bits: 1024, algorithm: protocol.RSA1024},
		{bits: 2048, algorithm: protocol.RSA2048},
		{bits: 3072, algorithm: protocol.RSA3072},
		{bits: 4096, algorithm: protocol.RSA4096},
	} {
		t.Run(fmt.Sprintf("RSA-%d", tc.bits), func(t *testing.T) {
			device, raw := newDevice(t)
			publicKey := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), uint(tc.bits-1)), E: 65537}

			key, err := device.PrivateKey(protocol.DigitalSignature, publicKey)
			if err != nil {
				t.Fatal(err)
			}

			if key.Public() != publicKey || raw.calls != 0 {
				t.Error("binding copied the public key or performed I/O")
			}

			if key.device != device || key.reference != protocol.DigitalSignature || key.algorithm != tc.algorithm {
				t.Errorf("binding device/reference/algorithm = %p/%02x/%02x, want %p/9c/%02x", key.device, key.reference, key.algorithm, device, tc.algorithm)
			}
		})
	}
}

func TestPrivateKeyBindsEllipticCurvesWithoutIOOrCopy(t *testing.T) {
	for _, tc := range []struct {
		curve     elliptic.Curve
		algorithm protocol.Algorithm
	}{
		{curve: elliptic.P256(), algorithm: protocol.ECCP256},
		{curve: elliptic.P384(), algorithm: protocol.ECCP384},
		{curve: elliptic.P521(), algorithm: protocol.ECCP521},
	} {
		t.Run(tc.curve.Params().Name, func(t *testing.T) {
			device, raw := newDevice(t)
			public := &signingECDSA(t, tc.curve).PublicKey

			key, err := device.PrivateKey(protocol.DigitalSignature, public)
			if err != nil {
				t.Fatal(err)
			}

			if key.Public() != public || raw.calls != 0 {
				t.Error("binding copied the public key or performed I/O")
			}

			if key.device != device || key.reference != protocol.DigitalSignature || key.algorithm != tc.algorithm {
				t.Errorf("binding device/reference/algorithm = %p/%02x/%02x, want %p/9c/%02x", key.device, key.reference, key.algorithm, device, tc.algorithm)
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

	if key.device != device || key.reference != protocol.DigitalSignature || key.algorithm != protocol.Ed25519 {
		t.Errorf("binding device/reference/algorithm = %p/%02x/%02x, want %p/9c/e0", key.device, key.reference, key.algorithm, device)
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

	if key.device != device || key.reference != protocol.KeyManagement || key.algorithm != protocol.X25519 {
		t.Errorf("binding device/reference/algorithm = %p/%02x/%02x, want %p/9d/e1", key.device, key.reference, key.algorithm, device)
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
