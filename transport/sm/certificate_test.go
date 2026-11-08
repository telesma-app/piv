package sm

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
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

func fixtureCertificate(t testing.TB, card *ecdh.PublicKey, signer *ecdsa.PrivateKey, issuer [8]byte) []byte {
	t.Helper()

	body := certificateBody(issuer, make([]byte, 16), card.Bytes(), 0)

	return signCertificate(t, body, signer, false)
}

func certificateBody(issuer [8]byte, subject, point []byte, role byte) []byte {
	body := bertlv.Append(nil, 0x5f29, []byte{0x80})
	body = bertlv.Append(body, 0x42, issuer[:])
	body = bertlv.Append(body, 0x5f20, subject)

	oid := []byte{0x2b, 0x81, 4, 0, 0x22}
	if len(point) == 65 {
		oid = []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7}
	}

	public := bertlv.Append(nil, 6, oid)
	public = bertlv.Append(public, 0x86, point)
	body = bertlv.Append(body, 0x7f49, public)

	return bertlv.Append(body, 0x5f4c, []byte{role})
}

func signCertificate(t testing.TB, body []byte, key crypto.PrivateKey, intermediate bool) []byte {
	t.Helper()

	algorithm := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}}

	var (
		signature []byte
		err       error
	)

	if intermediate {
		algorithm = pkix.AlgorithmIdentifier{Algorithm: oidRSASHA256, Parameters: asn1.NullRawValue}
		digest := sha256.Sum256(body)
		signature, err = rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, digest[:])
	} else if key.(*ecdsa.PrivateKey).Curve == elliptic.P256() {
		algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
		digest := sha256.Sum256(body)
		signature, err = ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), digest[:])
	} else {
		digest := sha512.Sum384(body)
		signature, err = ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), digest[:])
	}

	if err != nil {
		t.Fatal(err)
	}

	digitalSignature, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{Algorithm: algorithm, Signature: asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}})
	if err != nil {
		t.Fatal(err)
	}

	return bertlv.Append(nil, 0x7f21, bertlv.Append(body, 0x5f37, digitalSignature))
}

func certificateKeys(t testing.TB) (*ecdh.PrivateKey, *ecdsa.PrivateKey) {
	t.Helper()
	return certificateKeysForSuite(t, testCipherSuite(t, protocol.CipherSuite7))
}

func certificateKeysForSuite(t testing.TB, suite cipherSuite) (*ecdh.PrivateKey, *ecdsa.PrivateKey) {
	t.Helper()

	card, err := suite.curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := ecdsa.GenerateKey(suite.signingCurve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return card, signer
}

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

		if !bytes.Equal(got.Bytes(), card.PublicKey().Bytes()) {
			t.Errorf("verified public key = %x, want %x", got.Bytes(), card.PublicKey().Bytes())
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
			if got != nil || !errors.Is(err, test.want) {
				t.Errorf("verify = %v, %v, want %v", got, err, test.want)
			}
		})
	}
}

func mutateCertificate(raw []byte, index int) []byte {
	mutated := bytes.Clone(raw)
	mutated[index] ^= 1

	return mutated
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

func appendAlgorithmMembers(t testing.TB, signature, extra []byte) []byte {
	t.Helper()

	_, value, _, err := bertlv.Parse(signature)
	if err != nil {
		t.Fatal(err)
	}

	_, algorithm, rest, err := bertlv.Parse(value)
	if err != nil {
		t.Fatal(err)
	}

	algorithm = append(bytes.Clone(algorithm), extra...)
	value = append(bertlv.Append(nil, 0x30, algorithm), rest...)

	return bertlv.Append(nil, 0x30, value)
}

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
		raw := fixtureCertificate(t, card.PublicKey(), signer, [8]byte(identifier[:8]))

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
		if err != nil || got == nil || !bytes.Equal(got.Bytes(), card.PublicKey().Bytes()) {
			t.Fatalf("verify with intermediate = %v, %v", got, err)
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

func TestTrustFromCertificate(t *testing.T) {
	_, signer := certificateKeys(t)
	_, rootKey := certificateKeys(t)
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	options := x509.VerifyOptions{Roots: roots, CurrentTime: now}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test content signer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidContentSigning},
		SubjectKeyId: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
	}

	for _, test := range []struct {
		name     string
		change   func(*x509.Certificate, *x509.VerifyOptions)
		wantPass bool
	}{
		{name: "trusted content signer", change: func(*x509.Certificate, *x509.VerifyOptions) {}, wantPass: true},
		{name: "explicit roots required", change: func(_ *x509.Certificate, o *x509.VerifyOptions) { o.Roots = nil }},
		{name: "untrusted chain", change: func(_ *x509.Certificate, o *x509.VerifyOptions) { o.Roots = x509.NewCertPool() }},
		{name: "expired", change: func(_ *x509.Certificate, o *x509.VerifyOptions) { o.CurrentTime = now.Add(2 * time.Hour) }},
		{name: "missing digitalSignature", change: func(c *x509.Certificate, _ *x509.VerifyOptions) { c.KeyUsage = x509.KeyUsageKeyAgreement }},
		{name: "missing content signing EKU", change: func(c *x509.Certificate, _ *x509.VerifyOptions) { c.UnknownExtKeyUsage = nil }},
		{name: "short subjectKeyIdentifier", change: func(c *x509.Certificate, _ *x509.VerifyOptions) { c.SubjectKeyId = []byte{1} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			certTemplate, verifyOptions := *template, options
			test.change(&certTemplate, &verifyOptions)

			der, err := x509.CreateCertificate(rand.Reader, &certTemplate, root, &signer.PublicKey, rootKey)
			if err != nil {
				t.Fatal(err)
			}

			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}

			trust, err := TrustFromCertificate(cert, verifyOptions, nil)
			if test.wantPass {
				if err != nil || trust.IssuerID != ([8]byte{1, 2, 3, 4, 5, 6, 7, 8}) {
					t.Errorf("TrustFromCertificate = %v, %v", trust, err)
				}
			} else if !errors.Is(err, ErrAuthentication) {
				t.Errorf("TrustFromCertificate = %v, want authentication error", err)
			}
		})
	}
}

func TestTrustFromCertificateEnforcesChainEKU(t *testing.T) {
	_, rootKey := certificateKeys(t)
	_, caKey := certificateKeys(t)
	_, signer := certificateKeys(t)
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

	for _, test := range []struct {
		name     string
		caEKU    []x509.ExtKeyUsage
		caCustom []asn1.ObjectIdentifier
		caEmpty  bool
		rootEKU  []x509.ExtKeyUsage
		wantPass bool
	}{
		{name: "unrestricted CA", wantPass: true},
		{name: "PIV CA", caCustom: []asn1.ObjectIdentifier{oidContentSigning}, wantPass: true},
		{name: "Any CA", caEKU: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, wantPass: true},
		{name: "serverAuth CA", caEKU: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		{name: "empty CA EKU", caEmpty: true},
		{name: "serverAuth root", rootEKU: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
	} {
		t.Run(test.name, func(t *testing.T) {
			rootTemplate := &x509.Certificate{
				SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
				NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
				BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign,
				ExtKeyUsage: test.rootEKU,
			}
			root := issueTestCertificate(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)

			caTemplate := &x509.Certificate{
				SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test intermediate"},
				NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
				BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign,
				ExtKeyUsage: test.caEKU, UnknownExtKeyUsage: test.caCustom,
			}
			if test.caEmpty {
				caTemplate.ExtraExtensions = []pkix.Extension{{Id: oidExtendedUsage, Value: []byte{0x30, 0}}}
			}

			ca := issueTestCertificate(t, caTemplate, root, &caKey.PublicKey, rootKey)
			leafTemplate := &x509.Certificate{
				SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "test content signer"},
				NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
				KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidContentSigning},
				SubjectKeyId: []byte{1, 2, 3, 4, 5, 6, 7, 8},
			}
			leaf := issueTestCertificate(t, leafTemplate, ca, &signer.PublicKey, caKey)
			roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
			roots.AddCert(root)
			intermediates.AddCert(ca)

			_, err := TrustFromCertificate(leaf, x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now}, nil)
			if test.wantPass {
				if err != nil {
					t.Errorf("TrustFromCertificate = %v, want accepted chain", err)
				}
			} else if !errors.Is(err, ErrAuthentication) {
				t.Errorf("TrustFromCertificate = %v, want authentication error", err)
			}
		})
	}
}

func issueTestCertificate(t testing.TB, template, parent *x509.Certificate, public *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}
