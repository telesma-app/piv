package card

import (
	"bytes"
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
