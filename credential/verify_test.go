package credential

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
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

func TestVerifyCHUID(t *testing.T) {
	fixture := newSigningFixture(t, nil)
	chuid := fixtureCHUID(t, fixture)

	got, err := VerifyCHUID(chuid, fixture.options)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got.Raw, fixture.cert.Raw) {
		t.Error("returned a different signer")
	}

	for _, tc := range []struct {
		name string
		edit func(*protocol.CHUID, *x509.VerifyOptions)
	}{
		{"tampered content", func(c *protocol.CHUID, _ *x509.VerifyOptions) { c.Raw[3] ^= 1 }},
		{"tampered signature", func(c *protocol.CHUID, _ *x509.VerifyOptions) { c.IssuerSignature[len(c.IssuerSignature)-1] ^= 1 }},
		{"untrusted root", func(_ *protocol.CHUID, o *x509.VerifyOptions) { o.Roots = x509.NewCertPool() }},
		{"no roots", func(_ *protocol.CHUID, o *x509.VerifyOptions) { o.Roots = nil }},
		{"expired card", func(_ *protocol.CHUID, o *x509.VerifyOptions) {
			o.CurrentTime = time.Date(2032, 1, 1, 0, 0, 0, 0, time.UTC)
		}},
		{"expired certificate", func(_ *protocol.CHUID, o *x509.VerifyOptions) {
			o.CurrentTime = time.Date(2041, 1, 1, 0, 0, 0, 0, time.UTC)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := fixtureCHUID(t, fixture)
			o := fixture.options
			tc.edit(&c, &o)

			if _, err := VerifyCHUID(c, o); !errors.Is(err, ErrAuthentication) {
				t.Errorf("VerifyCHUID = %v, want authentication error", err)
			}
		})
	}

	options := fixture.options

	options.CurrentTime = time.Date(2031, 12, 31, 23, 59, 59, 999999999, time.UTC)
	if _, err := VerifyCHUID(chuid, options); err != nil {
		t.Errorf("last moment on expiry date rejected: %v", err)
	}
}

func TestVerifyCMSRejectsSignedAttributeMisuse(t *testing.T) {
	fixture := newSigningFixture(t, nil)
	content := []byte("external signed content")
	md := sha256.Sum256(content)

	base := []fixtureAttribute{fixtureAttr(t, oidContentType, oidCHUID), fixtureAttr(t, oidMessageDigest, md[:]), fixtureAttr(t, oidSignerDN, asn1.RawValue{FullBytes: fixture.cert.RawSubject})}
	for _, tc := range []struct {
		name  string
		attrs []fixtureAttribute
	}{
		{"missing digest", []fixtureAttribute{base[0], base[2]}},
		{"duplicate digest", append(slices.Clone(base), base[1])},
		{"wrong content type", []fixtureAttribute{fixtureAttr(t, oidContentType, oidBiometric), base[1], base[2]}},
		{"wrong signer DN", []fixtureAttribute{base[0], base[1], fixtureAttr(t, oidSignerDN, asn1.RawValue{FullBytes: fixture.cert.RawIssuer})}},
		{"wrong digest", []fixtureAttribute{base[0], fixtureAttr(t, oidMessageDigest, make([]byte, 32)), base[2]}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cms := fixtureCMS(t, fixture, content, oidCHUID, true, false, tc.attrs, nil)

			signed, err := parseCMS(cms)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := verifyCMS(signed, fixture.cert, content, oidCHUID, true); !errors.Is(err, ErrAuthentication) {
				t.Errorf("verifyCMS = %v", err)
			}
		})
	}
}

func TestVerifySecurityObjectAndEveryDataGroup(t *testing.T) {
	fixture := newSigningFixture(t, nil)
	data := map[protocol.ContainerID][]byte{0xdb00: {0xf5, 1, 0x10}, 0x3001: {1, 1, 'A'}}

	var hashes []protocol.DataGroupHash

	for i, container := range []protocol.ContainerID{0xdb00, 0x3001} {
		md := sha256.Sum256(data[container])
		hashes = append(hashes, protocol.DataGroupHash{DataGroup: uint8(i + 1), Digest: md[:]})
	}

	der, err := protocol.EncodeLDSSecurityObject(protocol.LDSSecurityObject{HashAlgorithm: crypto.SHA256, Hashes: hashes})
	if err != nil {
		t.Fatal(err)
	}

	for _, oid := range []asn1.ObjectIdentifier{oidLDS, oidLDSLegacy} {
		object := protocol.SecurityObjectData{Mapping: []protocol.DataGroupMapping{{DataGroup: 1, ContainerID: 0xdb00}, {DataGroup: 2, ContainerID: 0x3001}}, SignedData: fixtureCMS(t, fixture, der, oid, false, true, nil, nil)}

		lds, err := VerifySecurityObject(object, fixture.cert, fixture.options)
		if err != nil {
			t.Fatal(err)
		}

		if err := VerifyDataGroups(object, lds, data); err != nil {
			t.Fatal(err)
		}

		if err := VerifyDataGroups(object, lds, map[protocol.ContainerID][]byte{0xdb00: data[0xdb00]}); !errors.Is(err, ErrIntegrity) {
			t.Errorf("missing container = %v", err)
		}

		if err := VerifyDataGroups(object, lds, map[protocol.ContainerID][]byte{0xdb00: data[0xdb00], 0x3001: []byte("changed")}); !errors.Is(err, ErrIntegrity) {
			t.Errorf("changed container = %v", err)
		}

		object.Mapping[1].DataGroup = 3
		if _, err := VerifySecurityObject(object, fixture.cert, fixture.options); !errors.Is(err, ErrAuthentication) {
			t.Errorf("mapping mismatch = %v", err)
		}
	}
}

func TestGSASignedObjects(t *testing.T) {
	// Independent public GSA card-builder output; provenance is recorded in
	// testdata/gsa/README.md. Its certificate asserts a public test policy, so
	// authenticate signatures here and separately reject production trust.
	read := func(name string) []byte {
		t.Helper()

		data, err := os.ReadFile(filepath.Join("..", "testdata", "gsa", "card46-"+name+".bin"))
		if err != nil {
			t.Fatal(err)
		}

		return data
	}

	chuid, err := protocol.ParseCHUID(read("chuid"))
	if err != nil {
		t.Fatal(err)
	}

	cms, err := parseCMS(chuid.IssuerSignature)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := cmsCertificate(cms, nil, true)
	if err != nil {
		t.Fatal(err)
	}

	content := bytes.Clone(chuid.Raw[:79])

	content = append(content, 0xfe, 0)
	if _, err := verifyCMS(cms, signer, content, oidCHUID, true); err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(signer)

	if _, err := VerifyCHUID(chuid, x509.VerifyOptions{Roots: roots, CurrentTime: signer.NotBefore.Add(time.Hour)}); !errors.Is(err, ErrAuthentication) {
		t.Errorf("GSA test certificate accepted as production content signer: %v", err)
	}

	object, err := protocol.ParseSecurityObject(read("security-object"))
	if err != nil {
		t.Fatal(err)
	}

	signed, err := parseCMS(object.SignedData)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := cmsCertificate(signed, signer, false); err != nil {
		t.Fatal(err)
	}

	if _, err := verifyCMS(signed, signer, signed.Content.Content, oidLDSLegacy, false); err != nil {
		t.Fatal(err)
	}

	lds, err := protocol.ParseLDSSecurityObject(signed.Content.Content)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyDataGroups(object, lds, map[protocol.ContainerID][]byte{0x3000: read("chuid"), 0x6030: read("face"), 0x6010: read("fingerprints"), 0x3001: read("printed-information")}); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"face", "fingerprints"} {
		biometric, err := protocol.ParseBiometricData(read(name))
		if err != nil {
			t.Fatal(err)
		}

		signed, err := parseCMS(biometric.Signature)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := cmsCertificate(signed, signer, false); err != nil {
			t.Fatal(err)
		}

		attrs, err := verifyCMS(signed, signer, biometric.SignedData, oidBiometric, true)
		if err != nil {
			t.Fatal(err)
		}

		var fascn, guid []byte
		if err := attributeValue(attrs, oidFASCN, &fascn); err != nil {
			t.Fatal(err)
		}

		if err := attributeValue(attrs, oidEntryUUID, &guid); err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(fascn, chuid.FASCN[:]) || !bytes.Equal(guid, chuid.GUID[:]) {
			t.Errorf("GSA %s signed identifiers differ from CHUID", name)
		}
	}
}

func TestPSSOpenSSLInteroperability(t *testing.T) {
	read := func(name string) []byte {
		t.Helper()

		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}

		return b
	}

	block, _ := pem.Decode(read("pss-public-key.pem"))
	if block == nil {
		t.Fatal("missing OpenSSL public key")
	}

	public, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	md := sha256.Sum256(read("pss-message.txt"))
	// RFC 4055/8017: SHA-256 and MGF1/SHA-256 are explicit; saltLength20
	// and trailerField1 are DEFAULT values and absent in canonical DER.
	base, err := hex.DecodeString("a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500")
	if err != nil {
		t.Fatal(err)
	}

	for _, salt := range []int{0, 20, 32} {
		body := bytes.Clone(base)
		if salt != 20 {
			body = append(body, 0xa2, 3, 2, 1, byte(salt))
		}

		parameters := append([]byte{0x30, byte(len(body))}, body...)

		algorithm := pkix.AlgorithmIdentifier{Algorithm: oidRSAPSS, Parameters: asn1.RawValue{FullBytes: parameters}}
		for _, tc := range []struct {
			name string
			salt int
		}{{"pss-sha256-salt0.sig", 0}, {"pss-sha256-salt20.sig", 20}, {"pss-sha256-salt32.sig", 32}} {
			err := verifySignature(&x509.Certificate{PublicKey: public}, crypto.SHA256, algorithm, md[:], read(tc.name))
			if (err == nil) != (salt == tc.salt) {
				t.Errorf("PSS params salt%d / signature salt%d = %v", salt, tc.salt, err)
			}
		}
	}
}

func TestRSAAndPSSCMS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	fixture := newSigningFixture(t, key)

	content := []byte("signed PIV content")
	for _, salt := range []*int{nil, new(20), new(32)} {
		wire := fixtureCMS(t, fixture, content, oidCHUID, true, false, nil, salt)

		signed, err := parseCMS(wire)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := verifyCMS(signed, fixture.cert, content, oidCHUID, true); err != nil {
			t.Fatal(err)
		}
	}
}

func TestContentSigningCurveAndHashProfile(t *testing.T) {
	for _, tc := range []struct {
		curve elliptic.Curve
		hash  crypto.Hash
		valid bool
	}{
		{elliptic.P256(), crypto.SHA256, true}, {elliptic.P384(), crypto.SHA384, true},
		{elliptic.P256(), crypto.SHA384, false}, {elliptic.P384(), crypto.SHA256, false}, {elliptic.P521(), crypto.SHA256, false},
	} {
		key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		md := sha256.Sum256([]byte("PIV content"))
		hashed := md[:]
		algorithm := oidECDSA256

		if tc.hash == crypto.SHA384 {
			md384 := sha512.Sum384([]byte("PIV content"))
			hashed, algorithm = md384[:], oidECDSA384
		}

		signature, err := ecdsa.SignASN1(rand.Reader, key, hashed)
		if err != nil {
			t.Fatal(err)
		}

		err = verifySignature(&x509.Certificate{PublicKey: &key.PublicKey}, tc.hash, pkix.AlgorithmIdentifier{Algorithm: algorithm}, hashed, signature)
		if (err == nil) != tc.valid {
			t.Errorf("%s/%v = %v, valid=%v", tc.curve.Params().Name, tc.hash, err, tc.valid)
		}
	}
}
