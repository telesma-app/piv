package card

import (
	"bytes"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/telesma-app/piv/protocol"
)

func TestSignerCreatesVerifiableCertificateRequests(t *testing.T) {
	for _, tc := range []struct {
		name      string
		algorithm x509.SignatureAlgorithm
		key       protocol.Algorithm
	}{
		{name: "ECDSA P-256", algorithm: x509.ECDSAWithSHA256, key: protocol.ECCP256},
		{name: "ECDSA P-521", algorithm: x509.ECDSAWithSHA512, key: protocol.ECCP521},
		{name: "Ed25519", algorithm: x509.PureEd25519, key: protocol.Ed25519},
		{name: "RSA PKCS1v15", algorithm: x509.SHA256WithRSA, key: protocol.RSA2048},
		{name: "RSA PSS", algorithm: x509.SHA256WithRSAPSS, key: protocol.RSA2048},
		{name: "RSA-4096", algorithm: x509.SHA512WithRSA, key: protocol.RSA4096},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var key *PrivateKey

			var raw *signaturePeer

			switch tc.key {
			case protocol.RSA2048:
				key, raw = newRSASigningPeer(t)
			case protocol.RSA4096:
				key, raw = newRSASigningPeer(t)
				raw.rsa, raw.algorithm = signingRSA4096(t), protocol.RSA4096

				var err error

				key, err = key.device.PrivateKey(protocol.DigitalSignature, &raw.rsa.PublicKey)
				if err != nil {
					t.Fatal(err)
				}
			case protocol.ECCP521:
				key, raw = newECDSASigningPeer(t, elliptic.P521(), protocol.DigitalSignature)
			case protocol.Ed25519:
				key, raw = newEd25519SigningPeer(t, ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
			default:
				key, raw = newECDSASigningPeer(t, elliptic.P256(), 0x9c)
			}

			adapter := key.Signer(t.Context(), PINAuthentication(protocol.ApplicationPIN, signingPIN))
			if tc.key != protocol.Ed25519 && adapter.Public() != key.Public() {
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
