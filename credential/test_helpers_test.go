package credential

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/piv/protocol"
)

type signingFixture struct {
	key     crypto.Signer
	cert    *x509.Certificate
	options x509.VerifyOptions
	hash    crypto.Hash
}

func newSigningFixture(t testing.TB, key crypto.Signer) signingFixture {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PIV test CA"},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	if key == nil {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}

	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "PIV test content signer"},
		NotBefore: root.NotBefore, NotAfter: root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidContentSigning}, PolicyIdentifiers: []asn1.ObjectIdentifier{oidContentPolicy},
		SubjectKeyId: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
	}

	policy, err := x509.ParseOID(oidContentPolicy.String())
	if err != nil {
		t.Fatal(err)
	}

	leaf.Policies = []x509.OID{policy}

	der, err := x509.CreateCertificate(rand.Reader, leaf, root, key.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)

	return signingFixture{key: key, cert: certificate, options: x509.VerifyOptions{Roots: roots, CurrentTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}}
}

type fixtureAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

func fixtureAttr(t testing.TB, oid asn1.ObjectIdentifier, value any) fixtureAttribute {
	t.Helper()

	der, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return fixtureAttribute{Type: oid, Values: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: der}}
}

// The fixture builder follows the RFC 5652 ASN.1 independently: signature input
// is an explicit SET, while wire SignedAttributes replace its tag with A0.
func fixtureCMS(t testing.TB, fixture signingFixture, content []byte, typ asn1.ObjectIdentifier, embedded, attached bool, attrs []fixtureAttribute, pssSalt *int) []byte {
	t.Helper()

	hash := crypto.SHA256

	hashOID := oidSHA256
	if key, ok := fixture.key.(*ecdsa.PrivateKey); ok && key.Curve == elliptic.P384() {
		hash, hashOID = crypto.SHA384, oidSHA384
	}

	if fixture.hash != 0 {
		hash = fixture.hash
		if hash == crypto.SHA384 {
			hashOID = oidSHA384
		}
	}

	contentHash := hash.New()
	contentHash.Write(content)

	md := contentHash.Sum(nil)
	if attrs == nil {
		attrs = []fixtureAttribute{fixtureAttr(t, oidContentType, typ), fixtureAttr(t, oidMessageDigest, md), fixtureAttr(t, oidSignerDN, asn1.RawValue{FullBytes: fixture.cert.RawSubject})}
	}

	signedAttrs, err := asn1.MarshalWithParams(attrs, "set")
	if err != nil {
		t.Fatal(err)
	}

	attrsHash := hash.New()
	attrsHash.Write(signedAttrs)
	hashed := attrsHash.Sum(nil)

	algorithm := pkix.AlgorithmIdentifier{Algorithm: oidECDSA256}
	if hash == crypto.SHA384 {
		algorithm.Algorithm = oidECDSA384
	}

	var opts crypto.SignerOpts = hash

	if _, ok := fixture.key.(*rsa.PrivateKey); ok {
		algorithm = pkix.AlgorithmIdentifier{Algorithm: oidRSA, Parameters: asn1.NullRawValue}
	}

	if pssSalt != nil {
		opts = &rsa.PSSOptions{SaltLength: *pssSalt, Hash: crypto.SHA256}

		mgfHash, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue})
		if err != nil {
			t.Fatal(err)
		}

		params, err := asn1.Marshal(struct {
			Hash pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
			MGF  pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
			Salt int                      `asn1:"optional,explicit,tag:2,default:20"`
		}{pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}, pkix.AlgorithmIdentifier{Algorithm: oidMGF1, Parameters: asn1.RawValue{FullBytes: mgfHash}}, *pssSalt})
		if err != nil {
			t.Fatal(err)
		}

		algorithm = pkix.AlgorithmIdentifier{Algorithm: oidRSAPSS, Parameters: asn1.RawValue{FullBytes: params}}
	}

	signature, err := fixture.key.Sign(rand.Reader, hashed, opts)
	if err != nil {
		t.Fatal(err)
	}

	signedAttrs[0] = 0xa0

	var issuer asn1.RawValue
	if _, err := asn1.Unmarshal(fixture.cert.RawIssuer, &issuer); err != nil {
		t.Fatal(err)
	}

	sid, err := asn1.Marshal(struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}{issuer, fixture.cert.SerialNumber})
	if err != nil {
		t.Fatal(err)
	}

	type fixtureSignerInfo struct {
		Version   int
		SID       asn1.RawValue
		Digest    pkix.AlgorithmIdentifier
		Attrs     asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature []byte
	}

	type fixtureContent struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"optional,explicit,tag:0"`
	}

	encapsulated := fixtureContent{Type: typ}

	if attached {
		octets, err := asn1.Marshal(content)
		if err != nil {
			t.Fatal(err)
		}

		encapsulated.Content = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: octets}
	}

	certificate := asn1.RawValue{}
	if embedded {
		certificate = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: fixture.cert.Raw}
	}

	signed, err := asn1.Marshal(struct {
		Version      int
		Digests      []pkix.AlgorithmIdentifier `asn1:"set"`
		Content      fixtureContent
		Certificates asn1.RawValue       `asn1:"optional,tag:0"`
		Signers      []fixtureSignerInfo `asn1:"set"`
	}{3, []pkix.AlgorithmIdentifier{{Algorithm: hashOID, Parameters: asn1.NullRawValue}}, encapsulated, certificate, []fixtureSignerInfo{{1, asn1.RawValue{FullBytes: sid}, pkix.AlgorithmIdentifier{Algorithm: hashOID, Parameters: asn1.NullRawValue}, asn1.RawValue{FullBytes: signedAttrs}, algorithm, signature}}})
	if err != nil {
		t.Fatal(err)
	}

	result, err := asn1.Marshal(struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}{oidSignedData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: signed}})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func fixtureCHUID(t testing.TB, fixture signingFixture) protocol.CHUID {
	t.Helper()

	content := bertlv.Append(nil, 0x30, bytes.Repeat([]byte{0x42}, 25))
	content = bertlv.Append(content, 0x34, bytes.Repeat([]byte{0x17}, 16))
	content = bertlv.Append(content, 0x35, []byte("20311231"))
	// Include unknown fields and nonminimal BER length encoding in the signed
	// bytes. Re-encoding the parsed CHUID would invalidate the signature.
	content = append(content, 0x37, 0x81, 1, 0xab)
	content = append(content, 0xfe, 0)
	signature := fixtureCMS(t, fixture, content, oidCHUID, true, false, nil, nil)
	wire := bertlv.Append(content[:len(content)-2:len(content)-2], 0x3e, signature)
	wire = append(wire, 0xfe, 0)

	chuid, err := protocol.ParseCHUID(wire)
	if err != nil {
		t.Fatal(err)
	}

	return chuid
}
