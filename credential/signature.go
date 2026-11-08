package credential

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math/big"
)

// Signature and digest algorithms follow SP 800-78-5, Secs. 3.2.1 and 3.2.3.
var (
	oidSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidRSAPSS   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidMGF1     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidRSA256   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidRSA384   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidECDSA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
)

func verifySignature(certificate *x509.Certificate, hash crypto.Hash, algorithm pkix.AlgorithmIdentifier, digest, signature []byte) error {
	// SP 800-78-5, Table 2 defines content-signing key/hash combinations,
	// independently of the card's private-key command algorithm identifiers.
	switch key := certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		if bits := key.N.BitLen(); bits != 2048 && bits != 3072 && bits != 4096 {
			return fmt.Errorf("unsupported PIV content-signing RSA key size")
		}
	case *ecdsa.PublicKey:
		supported := key.Curve == elliptic.P256() && hash == crypto.SHA256 ||
			key.Curve == elliptic.P384() && hash == crypto.SHA384
		if !supported {
			return fmt.Errorf("unsupported PIV content-signing curve/hash combination")
		}
	default:
		return fmt.Errorf("unsupported PIV content-signing public key")
	}

	switch {
	case algorithm.Algorithm.Equal(oidRSA), algorithm.Algorithm.Equal(oidRSA256), algorithm.Algorithm.Equal(oidRSA384):
		if !algorithm.Algorithm.Equal(oidRSA) && ((hash == crypto.SHA256) != algorithm.Algorithm.Equal(oidRSA256)) {
			return fmt.Errorf("signature and digest algorithms disagree")
		}

		if p := algorithm.Parameters.FullBytes; len(p) != 0 && !bytes.Equal(p, asn1.NullBytes) {
			return fmt.Errorf("invalid RSA signature parameters")
		}

		key, ok := certificate.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("RSA signature with non-RSA certificate")
		}

		return rsa.VerifyPKCS1v15(key, hash, digest, signature)
	case algorithm.Algorithm.Equal(oidRSAPSS):
		var params struct {
			Hash    pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
			MGF     pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
			Salt    int                      `asn1:"optional,explicit,tag:2,default:20"`
			Trailer int                      `asn1:"optional,explicit,tag:3,default:1"`
		}
		if err := decode(algorithm.Parameters.FullBytes, &params); err != nil {
			return err
		}

		fields, err := sequenceFields(algorithm.Parameters.FullBytes)
		if err != nil || len(fields) < 2 || len(fields) > 4 {
			return fmt.Errorf("invalid RSA-PSS parameter sequence")
		}

		if err := checkAlgorithmEncoding(params.MGF.Parameters.FullBytes); err != nil {
			return err
		}

		mgfHash := pkix.AlgorithmIdentifier{}
		if err := decode(params.MGF.Parameters.FullBytes, &mgfHash); err != nil {
			return err
		}

		pssHash, err := digestAlgorithm(params.Hash)
		if err != nil {
			return err
		}

		maskHash, err := digestAlgorithm(mgfHash)
		if err != nil {
			return err
		}

		if pssHash != hash || maskHash != hash || !params.MGF.Algorithm.Equal(oidMGF1) || params.Salt < 0 || params.Salt > hash.Size() || params.Trailer != 1 {
			return fmt.Errorf("invalid PIV RSA-PSS parameters")
		}

		key, ok := certificate.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("RSA-PSS signature with non-RSA certificate")
		}
		// SaltLength=0 means auto-detection in crypto/rsa, whereas CMS means
		// an exactly empty salt. Verify its encoded length explicitly below.
		if params.Salt == 0 {
			return verifyPSSZeroSalt(key, hash, digest, signature)
		}

		return rsa.VerifyPSS(key, hash, digest, signature, &rsa.PSSOptions{SaltLength: params.Salt, Hash: hash})
	case algorithm.Algorithm.Equal(oidECDSA256), algorithm.Algorithm.Equal(oidECDSA384):
		if ((hash == crypto.SHA256) != algorithm.Algorithm.Equal(oidECDSA256)) || len(algorithm.Parameters.FullBytes) != 0 {
			return fmt.Errorf("invalid ECDSA signature algorithm or parameters")
		}

		key, ok := certificate.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("ECDSA signature with non-ECDSA certificate")
		}

		if !ecdsa.VerifyASN1(key, digest, signature) {
			return fmt.Errorf("invalid ECDSA signature")
		}

		return nil
	default:
		return fmt.Errorf("unsupported PIV signature algorithm %s", algorithm.Algorithm)
	}
}

// crypto/rsa reserves SaltLength=0 for automatic detection. Construct the
// deterministic EMSA-PSS encoding for the actual empty-salt case (RFC 8017,
// Sec. 9.1.1), using only public RSA operations.
func verifyPSSZeroSalt(key *rsa.PublicKey, hash crypto.Hash, hashed, signature []byte) error {
	if len(signature) != key.Size() {
		return rsa.ErrVerification
	}

	s := new(big.Int).SetBytes(signature)
	if s.Cmp(key.N) >= 0 {
		return rsa.ErrVerification
	}

	emBits := key.N.BitLen() - 1

	emLen := (emBits + 7) / 8
	if emLen < hash.Size()+2 {
		return rsa.ErrVerification
	}

	m := append(make([]byte, 8), hashed...)
	h := digest(hash, m)
	db := make([]byte, emLen-hash.Size()-1)

	db[len(db)-1] = 1
	for offset, counter := 0, uint32(0); offset < len(db); counter++ {
		input := append(bytes.Clone(h), binary.BigEndian.AppendUint32(nil, counter)...)

		mask := digest(hash, input)
		for _, b := range mask {
			if offset == len(db) {
				break
			}

			db[offset] ^= b
			offset++
		}
	}

	db[0] &= byte(0xff >> (8*emLen - emBits))
	expected := append(db, h...)
	expected = append(expected, 0xbc)

	actual := new(big.Int).Exp(s, big.NewInt(int64(key.E)), key.N)
	if actual.Cmp(new(big.Int).SetBytes(expected)) != 0 {
		return rsa.ErrVerification
	}

	return nil
}

func digestAlgorithm(algorithm pkix.AlgorithmIdentifier) (crypto.Hash, error) {
	if p := algorithm.Parameters.FullBytes; len(p) != 0 && !bytes.Equal(p, asn1.NullBytes) {
		return 0, fmt.Errorf("%w: invalid digest parameters", ErrAuthentication)
	}

	switch {
	case algorithm.Algorithm.Equal(oidSHA256):
		return crypto.SHA256, nil
	case algorithm.Algorithm.Equal(oidSHA384):
		return crypto.SHA384, nil
	default:
		return 0, fmt.Errorf("%w: unsupported PIV digest algorithm %s", ErrAuthentication, algorithm.Algorithm)
	}
}

func digest(hash crypto.Hash, data []byte) []byte {
	switch hash {
	case crypto.SHA256:
		hash := sha256.Sum256(data)
		return hash[:]
	case crypto.SHA384:
		hash := sha512.Sum384(data)
		return hash[:]
	default:
		panic("unsupported PIV digest algorithm")
	}
}
