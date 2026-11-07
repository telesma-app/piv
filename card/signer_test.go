package card

import (
	"bytes"
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"

	"github.com/telesma-app/piv/protocol"
)

func TestSignerCreatesVerifiableCertificateRequests(t *testing.T) {
	for _, tc := range []struct {
		name      string
		algorithm x509.SignatureAlgorithm
		rsa       bool
	}{
		{name: "ECDSA", algorithm: x509.ECDSAWithSHA256},
		{name: "RSA PKCS1v15", algorithm: x509.SHA256WithRSA, rsa: true},
		{name: "RSA PSS", algorithm: x509.SHA256WithRSAPSS, rsa: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var key *PrivateKey

			var raw *signaturePeer
			if tc.rsa {
				key, raw = newRSASigningPeer(t)
			} else {
				key, raw = newECDSASigningPeer(t, elliptic.P256(), 0x9c)
			}

			adapter := key.Signer(t.Context(), PINAuthentication(protocol.ApplicationPIN, signingPIN))
			if adapter.Public() != key.Public() {
				t.Fatal("Signer.Public returned a different public key")
			}

			template := &x509.CertificateRequest{
				Subject: pkix.Name{CommonName: "PIV CSR"}, SignatureAlgorithm: tc.algorithm,
				DNSNames: []string{"signing.example"},
			}

			der, err := x509.CreateCertificateRequest(rand.Reader, template, adapter)
			if err != nil {
				t.Fatal(err)
			}

			request, err := x509.ParseCertificateRequest(der)
			if err != nil {
				t.Fatal(err)
			}

			if err := request.CheckSignature(); err != nil {
				t.Fatal(err)
			}

			if request.Subject.CommonName != template.Subject.CommonName || request.SignatureAlgorithm != tc.algorithm {
				t.Errorf("CSR subject/algorithm = %s/%s", request.Subject.CommonName, request.SignatureAlgorithm)
			}

			encodedPublic, err := x509.MarshalPKIXPublicKey(key.Public())
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(request.RawSubjectPublicKeyInfo, encodedPublic) || raw.verifies != 1 || raw.signatures != 1 {
				t.Error("CSR changed the key or did not perform exactly one PIN/sign operation")
			}
		})
	}
}

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
