package sm

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/piv/protocol"
)

func TestCertificateAuthenticatesExactSignedBytes(t *testing.T) {
	testCipherSuites(t, func(t *testing.T, suite cipherSuite) {
		card, signer := certificateKeysForSuite(t, suite)
		issuer := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
		body := certificateBody(issuer, make([]byte, 16), card.PublicKey().Bytes(), 0)
		// BER permits this long-form length. The signature authenticates its exact
		// encoding, rather than a reconstructed canonical form of the fields.
		body = append([]byte{0x5f, 0x29, 0x81, 1}, body[3:]...)
		raw := signCertificate(t, body, signer, false)

		got, err := verifyCertificate(suite, raw, Trust{IssuerID: issuer, PublicKey: &signer.PublicKey})
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(got.PublicKey.Bytes(), card.PublicKey().Bytes()) {
			t.Errorf("verified public key = %x, want %x", got.PublicKey.Bytes(), card.PublicKey().Bytes())
		}
	})
}

func TestCertificateRejectsTamperingAndWrongTrust(t *testing.T) {
	card, signer := certificateKeys(t)
	issuer := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	trust := Trust{IssuerID: issuer, PublicKey: &signer.PublicKey}
	raw := fixtureCertificate(t, card.PublicKey(), signer, issuer)
	_, otherSigner := certificateKeys(t)

	p256Signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name  string
		input []byte
		trust Trust
		want  error
	}{
		{name: "wrong issuer", input: raw, trust: Trust{IssuerID: [8]byte{9}, PublicKey: &signer.PublicKey}, want: ErrAuthentication},
		{name: "wrong signer", input: raw, trust: Trust{IssuerID: issuer, PublicKey: &otherSigner.PublicKey}, want: ErrAuthentication},
		{name: "wrong signer curve", input: raw, trust: Trust{IssuerID: issuer, PublicKey: &p256Signer.PublicKey}, want: ErrAuthentication},
		{name: "signature tampered", input: mutateCertificate(raw, len(raw)-1), trust: trust, want: ErrAuthentication},
		{name: "trailing bytes", input: append(bytes.Clone(raw), 0), trust: trust, want: ErrInvalidResponse},
		{name: "truncated certificate", input: raw[:len(raw)-1], trust: trust, want: ErrInvalidResponse},
		{name: "wrong profile", input: signCertificate(t, certificateBodyWith(t, issuer, card.PublicKey().Bytes(), 0x5f29, []byte{0}), signer, false), trust: trust, want: ErrInvalidResponse},
		{name: "wrong role", input: signCertificate(t, certificateBody(issuer, make([]byte, 16), card.PublicKey().Bytes(), 0x12), signer, false), trust: trust, want: ErrInvalidResponse},
		{name: "invalid point", input: signCertificate(t, certificateBody(issuer, make([]byte, 16), append([]byte{4}, make([]byte, 96)...), 0), signer, false), trust: trust, want: ErrAuthentication},
		{name: "short subject", input: signCertificate(t, certificateBody(issuer, make([]byte, 8), card.PublicKey().Bytes(), 0), signer, false), trust: trust, want: ErrInvalidResponse},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := verifyCertificate(testCipherSuite(t, protocol.CipherSuite7), test.input, test.trust)
			if got.PublicKey != nil || got.Raw != nil || got.GUID != [16]byte{} || !errors.Is(err, test.want) {
				t.Errorf("verify = %v, %v, want %v", got, err, test.want)
			}
		})
	}
}

func TestCertificateRejectsOtherCipherSuite(t *testing.T) {
	testCipherSuites(t, func(t *testing.T, suite cipherSuite) {
		otherAlgorithm := protocol.CipherSuite2
		if suite.algorithm == otherAlgorithm {
			otherAlgorithm = protocol.CipherSuite7
		}

		other := testCipherSuite(t, otherAlgorithm)
		card, signer := certificateKeysForSuite(t, suite)
		otherCard, otherSigner := certificateKeysForSuite(t, other)
		issuer := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}

		for _, test := range []struct {
			name   string
			card   *ecdh.PublicKey
			signer *ecdsa.PrivateKey
		}{
			{name: "card curve", card: otherCard.PublicKey(), signer: signer},
			{name: "signer curve", card: card.PublicKey(), signer: otherSigner},
		} {
			t.Run(test.name, func(t *testing.T) {
				raw := fixtureCertificate(t, test.card, test.signer, issuer)

				trust := Trust{IssuerID: issuer, PublicKey: &test.signer.PublicKey}
				if _, err := verifyCertificate(suite, raw, trust); !errors.Is(err, ErrAuthentication) {
					t.Fatalf("verify other-suite CVC = %v", err)
				}
			})
		}
	})
}

func TestCertificateRejectsSignatureEncodingAndAlgorithm(t *testing.T) {
	testCipherSuites(t, func(t *testing.T, suite cipherSuite) {
		card, signer := certificateKeysForSuite(t, suite)
		issuer := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
		raw := fixtureCertificate(t, card.PublicKey(), signer, issuer)

		_, body, _, err := bertlv.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}

		var signatureValue []byte

		for data := body; len(data) != 0; {
			tag, value, rest, err := bertlv.Parse(data)
			if err != nil {
				t.Fatal(err)
			}

			if tag == 0x5f37 {
				signatureValue = value
				body = body[:len(body)-len(data)]

				break
			}

			data = rest
		}

		var signature struct {
			Algorithm pkix.AlgorithmIdentifier
			Value     asn1.BitString
		}
		if _, err := asn1.Unmarshal(signatureValue, &signature); err != nil {
			t.Fatal(err)
		}

		for _, test := range []struct {
			name   string
			change func() []byte
			want   error
		}{
			{name: "wrong hash", change: func() []byte {
				value := signature

				value.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
				if suite.algorithm == protocol.CipherSuite2 {
					value.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
				}

				encoded, err := asn1.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}

				return encoded
			}, want: ErrAuthentication},
			{name: "ECDSA parameters present", change: func() []byte {
				value := signature
				value.Algorithm.Parameters = asn1.NullRawValue

				encoded, err := asn1.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}

				return encoded
			}, want: ErrAuthentication},
			{name: "extra DigitalSignature member", change: func() []byte {
				_, value, _, err := bertlv.Parse(signatureValue)
				if err != nil {
					t.Fatal(err)
				}

				value = append(bytes.Clone(value), 5, 0)

				return bertlv.Append(nil, 0x30, value)
			}, want: ErrInvalidResponse},
			{name: "extra AlgorithmIdentifier member", change: func() []byte {
				return appendAlgorithmMembers(t, signatureValue, []byte{5, 0, 5, 0})
			}, want: ErrInvalidResponse},
			{name: "DigitalSignature trailing bytes", change: func() []byte {
				return append(bytes.Clone(signatureValue), 5, 0)
			}, want: ErrInvalidResponse},
		} {
			t.Run(test.name, func(t *testing.T) {
				modified := bertlv.Append(nil, 0x7f21, bertlv.Append(bytes.Clone(body), 0x5f37, test.change()))

				_, err := verifyCertificate(suite, modified, Trust{IssuerID: issuer, PublicKey: &signer.PublicKey})
				if !errors.Is(err, test.want) {
					t.Errorf("verify = %v, want %v", err, test.want)
				}
			})
		}
	})
}

func TestCertificateAuthenticatesIntermediateCVC(t *testing.T) {
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
		trust := Trust{IssuerID: issuer, PublicKey: &root.PublicKey, IntermediateCVC: intermediate}

		got, err := verifyCertificate(suite, raw, trust)
		if err != nil {
			t.Fatal(err)
		}

		if got.PublicKey == nil || !bytes.Equal(got.PublicKey.Bytes(), card.PublicKey().Bytes()) || got.GUID != guid || !bytes.Equal(got.Raw, raw) {
			t.Errorf("verified card identity = %+v, want GUID %x and original CVC/public key", got, guid)
		}

		for _, tc := range []struct {
			name         string
			intermediate []byte
			want         error
		}{
			{name: "signature tampered", intermediate: mutateCertificate(intermediate, len(intermediate)-1), want: ErrAuthentication},
			{name: "wrong issuer", intermediate: signCertificate(t, certificateBody([8]byte{9}, identifier[:8], point, 0x12), root, true), want: ErrAuthentication},
			{name: "wrong subject identifier", intermediate: signCertificate(t, certificateBody(issuer, make([]byte, 8), point, 0x12), root, true), want: ErrAuthentication},
			{name: "wrong role", intermediate: signCertificate(t, certificateBody(issuer, identifier[:8], point, 0), root, true), want: ErrInvalidResponse},
			{name: "extra RSA AlgorithmIdentifier member", intermediate: appendCertificateAlgorithmMembers(t, intermediate, []byte{5, 0}), want: ErrInvalidResponse},
		} {
			t.Run(tc.name, func(t *testing.T) {
				badTrust := trust
				badTrust.IntermediateCVC = tc.intermediate

				got, err := verifyCertificate(suite, raw, badTrust)
				if !errors.Is(err, tc.want) || got.PublicKey != nil || got.Raw != nil || got.GUID != [16]byte{} {
					t.Errorf("verifyCertificate = %+v, %v; want %v without a card identity", got, err, tc.want)
				}
			})
		}
	})
}

func certificateBodyWith(t testing.TB, issuer [8]byte, point []byte, replace uint32, replacement []byte) []byte {
	t.Helper()

	var body []byte

	data := certificateBody(issuer, make([]byte, 16), point, 0)
	for len(data) != 0 {
		tag, value, rest, err := bertlv.Parse(data)
		if err != nil {
			t.Fatal(err)
		}

		if tag == replace {
			value = replacement
		}

		body = bertlv.Append(body, tag, value)
		data = rest
	}

	return body
}
