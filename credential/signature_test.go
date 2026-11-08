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
	"os"
	"path/filepath"
	"testing"
)

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
