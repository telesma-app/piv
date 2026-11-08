package sm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/piv/protocol"
)

func appendCertificateAlgorithmMembers(t testing.TB, raw, extra []byte) []byte {
	t.Helper()

	_, body, _, err := bertlv.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	for data := body; len(data) != 0; {
		tag, value, rest, err := bertlv.Parse(data)
		if err != nil {
			t.Fatal(err)
		}

		if tag == 0x5f37 {
			body = bytes.Clone(body[:len(body)-len(data)])
			body = bertlv.Append(body, 0x5f37, appendAlgorithmMembers(t, value, extra))

			return bertlv.Append(nil, 0x7f21, body)
		}

		data = rest
	}

	t.Fatal("fixture certificate lacks signature")

	return nil
}

func TestIntermediateCertificateTrust(t *testing.T) {
	testCipherSuites(t, func(t *testing.T, suite cipherSuite) {
		card, signer := certificateKeysForSuite(t, suite)

		root, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}

		issuer := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}

		signerECDH, err := signer.ECDH()
		if err != nil {
			t.Fatal(err)
		}

		point := signerECDH.PublicKey().Bytes()
		identifier := sha1.Sum(point)
		body := certificateBody(issuer, identifier[:8], point, 0x12)
		body = append([]byte{0x5f, 0x29, 0x81, 1}, body[3:]...)
		intermediate := signCertificate(t, body, root, true)
		guid := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		raw := signCertificate(t, certificateBody([8]byte(identifier[:8]), guid[:], card.PublicKey().Bytes(), 0), signer, false)

		caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
		caTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign,
		}

		caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}

		ca, err := x509.ParseCertificate(caDER)
		if err != nil {
			t.Fatal(err)
		}

		signerTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "RSA content signer"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidContentSigning},
			SubjectKeyId: issuer[:],
		}

		signerDER, err := x509.CreateCertificate(rand.Reader, signerTemplate, ca, &root.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}

		object := bertlv.Append(nil, 0x70, signerDER)
		object = append(object, 0x71, 1, 0)
		object = append(object, intermediate...)
		object = append(object, 0xfe, 0)

		signerData, err := protocol.ParseSecureMessagingCertificateSigner(object)
		if err != nil {
			t.Fatal(err)
		}

		contentSigner, err := x509.ParseCertificate(signerData.CertificateDER)
		if err != nil {
			t.Fatal(err)
		}

		roots := x509.NewCertPool()
		roots.AddCert(ca)

		trust, err := TrustFromCertificate(contentSigner, x509.VerifyOptions{Roots: roots, CurrentTime: now}, signerData.IntermediateCVC)
		if err != nil {
			t.Fatal(err)
		}

		got, err := verifyCertificate(suite, raw, trust)
		if err != nil || got.PublicKey == nil || !bytes.Equal(got.PublicKey.Bytes(), card.PublicKey().Bytes()) {
			t.Fatalf("verify with intermediate = %v, %v", got, err)
		}

		if got.GUID != guid || !bytes.Equal(got.Raw, raw) {
			t.Fatalf("verified card identity = %+v, want GUID %x, CVC %x", got, guid, raw)
		}

		for _, test := range []struct {
			name         string
			intermediate []byte
			want         error
		}{
			{name: "signature tampered", intermediate: mutateCertificate(intermediate, len(intermediate)-1), want: ErrAuthentication},
			{name: "wrong issuer", intermediate: signCertificate(t, certificateBody([8]byte{9}, identifier[:8], point, 0x12), root, true), want: ErrAuthentication},
			{name: "wrong subject identifier", intermediate: signCertificate(t, certificateBody(issuer, make([]byte, 8), point, 0x12), root, true), want: ErrAuthentication},
			{name: "extra RSA AlgorithmIdentifier member", intermediate: appendCertificateAlgorithmMembers(t, intermediate, []byte{5, 0}), want: ErrInvalidResponse},
		} {
			t.Run(test.name, func(t *testing.T) {
				badTrust := trust

				badTrust.IntermediateCVC = test.intermediate
				if _, err := verifyCertificate(suite, raw, badTrust); !errors.Is(err, test.want) {
					t.Errorf("verify = %v, want %v", err, test.want)
				}
			})
		}
	})
}
