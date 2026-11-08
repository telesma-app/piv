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

func TestSignatureAlgorithmIdentifiers(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	md := sha256.Sum256([]byte("PIV algorithm identifier profile"))

	rsaSignature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, md[:])
	if err != nil {
		t.Fatal(err)
	}

	ecSignature, err := ecdsa.SignASN1(rand.Reader, ecKey, md[:])
	if err != nil {
		t.Fatal(err)
	}

	rsaOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	rsa256OID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	rsa384OID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	ec256OID := asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	ec384OID := asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}

	for _, tc := range []struct {
		name      string
		public    crypto.PublicKey
		algorithm pkix.AlgorithmIdentifier
		signature []byte
		valid     bool
	}{
		{name: "RSA absent parameters", public: &rsaKey.PublicKey, algorithm: pkix.AlgorithmIdentifier{Algorithm: rsaOID}, signature: rsaSignature, valid: true},
		{name: "RSA NULL parameters", public: &rsaKey.PublicKey, algorithm: pkix.AlgorithmIdentifier{Algorithm: rsaOID, Parameters: asn1.RawValue{FullBytes: asn1.NullBytes}}, signature: rsaSignature, valid: true},
		{name: "RSA SHA256 OID", public: &rsaKey.PublicKey, algorithm: pkix.AlgorithmIdentifier{Algorithm: rsa256OID}, signature: rsaSignature, valid: true},
		{name: "RSA invalid parameters", public: &rsaKey.PublicKey, algorithm: pkix.AlgorithmIdentifier{Algorithm: rsaOID, Parameters: asn1.RawValue{FullBytes: []byte{1, 1, 0xff}}}, signature: rsaSignature},
		{name: "RSA OID and digest mismatch", public: &rsaKey.PublicKey, algorithm: pkix.AlgorithmIdentifier{Algorithm: rsa384OID}, signature: rsaSignature},
		{name: "ECDSA absent parameters", public: &ecKey.PublicKey, algorithm: pkix.AlgorithmIdentifier{Algorithm: ec256OID}, signature: ecSignature, valid: true},
		{name: "ECDSA NULL parameters", public: &ecKey.PublicKey, algorithm: pkix.AlgorithmIdentifier{Algorithm: ec256OID, Parameters: asn1.RawValue{FullBytes: asn1.NullBytes}}, signature: ecSignature},
		{name: "ECDSA OID and digest mismatch", public: &ecKey.PublicKey, algorithm: pkix.AlgorithmIdentifier{Algorithm: ec384OID}, signature: ecSignature},
		{name: "RSA OID with ECDSA key", public: &ecKey.PublicKey, algorithm: pkix.AlgorithmIdentifier{Algorithm: rsaOID}, signature: ecSignature},
		{name: "ECDSA OID with RSA key", public: &rsaKey.PublicKey, algorithm: pkix.AlgorithmIdentifier{Algorithm: ec256OID}, signature: rsaSignature},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifySignature(&x509.Certificate{PublicKey: tc.public}, crypto.SHA256, tc.algorithm, md[:], tc.signature)
			if (err == nil) != tc.valid {
				t.Errorf("verifySignature = %v, valid=%t", err, tc.valid)
			}
		})
	}
}

func TestPSSAlgorithmIdentifierProfile(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	md := sha256.Sum256([]byte("PIV RSA-PSS parameter profile"))
	sha256OID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	sha384OID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	mgf1OID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	otherMaskOID := asn1.ObjectIdentifier{1, 2, 3, 4}

	for _, tc := range []struct {
		name          string
		hashOID       asn1.ObjectIdentifier
		maskHashOID   asn1.ObjectIdentifier
		maskOID       asn1.ObjectIdentifier
		salt          int
		signatureSalt int
		trailer       int
		valid         bool
	}{
		{name: "default salt and trailer", hashOID: sha256OID, maskHashOID: sha256OID, maskOID: mgf1OID, salt: 20, signatureSalt: 20, trailer: 1, valid: true},
		{name: "hash sized salt", hashOID: sha256OID, maskHashOID: sha256OID, maskOID: mgf1OID, salt: 32, signatureSalt: 32, trailer: 1, valid: true},
		{name: "digest mismatch", hashOID: sha384OID, maskHashOID: sha256OID, maskOID: mgf1OID, salt: 20, signatureSalt: 20, trailer: 1},
		{name: "MGF digest mismatch", hashOID: sha256OID, maskHashOID: sha384OID, maskOID: mgf1OID, salt: 20, signatureSalt: 20, trailer: 1},
		{name: "unsupported MGF", hashOID: sha256OID, maskHashOID: sha256OID, maskOID: otherMaskOID, salt: 20, signatureSalt: 20, trailer: 1},
		{name: "negative salt", hashOID: sha256OID, maskHashOID: sha256OID, maskOID: mgf1OID, salt: -1, signatureSalt: 32, trailer: 1},
		{name: "salt exceeds digest size", hashOID: sha256OID, maskHashOID: sha256OID, maskOID: mgf1OID, salt: 33, signatureSalt: 33, trailer: 1},
		{name: "unsupported trailer", hashOID: sha256OID, maskHashOID: sha256OID, maskOID: mgf1OID, salt: 20, signatureSalt: 20, trailer: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The signature remains valid for SHA-256, including non-PIV salt
			// lengths. Each negative case changes only its declared CMS profile.
			signature, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, md[:], &rsa.PSSOptions{SaltLength: tc.signatureSalt, Hash: crypto.SHA256})
			if err != nil {
				t.Fatal(err)
			}

			maskHash, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: tc.maskHashOID, Parameters: asn1.NullRawValue})
			if err != nil {
				t.Fatal(err)
			}

			parameters, err := asn1.Marshal(struct {
				Hash    pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
				MGF     pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
				Salt    int                      `asn1:"optional,explicit,tag:2,default:20"`
				Trailer int                      `asn1:"optional,explicit,tag:3,default:1"`
			}{
				Hash: pkix.AlgorithmIdentifier{Algorithm: tc.hashOID, Parameters: asn1.NullRawValue},
				MGF:  pkix.AlgorithmIdentifier{Algorithm: tc.maskOID, Parameters: asn1.RawValue{FullBytes: maskHash}},
				Salt: tc.salt, Trailer: tc.trailer,
			})
			if err != nil {
				t.Fatal(err)
			}

			algorithm := pkix.AlgorithmIdentifier{
				Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10},
				Parameters: asn1.RawValue{FullBytes: parameters},
			}

			err = verifySignature(&x509.Certificate{PublicKey: &key.PublicKey}, crypto.SHA256, algorithm, md[:], signature)
			if (err == nil) != tc.valid {
				t.Errorf("verifySignature = %v, valid=%t", err, tc.valid)
			}
		})
	}
}
