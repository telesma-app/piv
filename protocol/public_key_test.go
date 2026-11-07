package protocol

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/telesma-app/piv/internal/bertlv"
)

func TestParseRSAPublicKey(t *testing.T) {
	for _, tt := range []struct {
		name      string
		algorithm Algorithm
		bits      int
	}{
		{name: "RSA 1024", algorithm: RSA1024, bits: 1024},
		{name: "RSA 2048", algorithm: RSA2048, bits: 2048},
		{name: "RSA 3072", algorithm: RSA3072, bits: 3072},
	} {
		t.Run(tt.name, func(t *testing.T) {
			modulus := bytes.Repeat([]byte{0xab}, tt.bits/8)
			data := bertlv.Append(nil, 0x81, modulus)
			data = bertlv.Append(data, 0x82, []byte{0x01, 0x00, 0x01})
			data = bertlv.Append(nil, 0x7f49, data)

			parsed, err := ParsePublicKey(tt.algorithm, data)
			if err != nil {
				t.Fatal(err)
			}

			key, ok := parsed.(*rsa.PublicKey)
			if !ok {
				t.Fatalf("key type = %T, want *rsa.PublicKey", parsed)
			}

			if !bytes.Equal(key.N.Bytes(), modulus) || key.E != 65537 {
				t.Errorf("key = %v, want modulus %x and E 65537", key, modulus)
			}
		})
	}
}

func TestParseRSA3072PublicKeyWire(t *testing.T) {
	// SP 800-73-5 Part 1, Table 6 assigns mechanism 05 to RSA-3072.
	if RSA3072 != 0x05 {
		t.Fatalf("RSA3072 = %02x, want 05", byte(RSA3072))
	}

	modulus := bytes.Repeat([]byte{0xab}, 384)
	data := append([]byte{0x7f, 0x49, 0x82, 0x01, 0x89, 0x81, 0x82, 0x01, 0x80}, modulus...)
	data = append(data, 0x82, 0x03, 0x01, 0x00, 0x01)

	parsed, err := ParsePublicKey(RSA3072, data)
	if err != nil {
		t.Fatal(err)
	}

	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("key type = %T, want *rsa.PublicKey", parsed)
	}

	if key.N.BitLen() != 3072 || !bytes.Equal(key.N.Bytes(), modulus) || key.E != 65537 {
		t.Errorf("key = %v, want RSA-3072 modulus and exponent 65537", key)
	}

	if _, err := ParsePublicKey(RSA2048, data); !errors.Is(err, ErrInvalidResponse) {
		t.Errorf("RSA-3072 response for RSA-2048 request = %v, want ErrInvalidResponse", err)
	}
}

func TestParseRSAPublicExponentUsesNumericRange(t *testing.T) {
	modulus := bytes.Repeat([]byte{0xab}, 256)
	data := bertlv.Append(nil, 0x81, modulus)
	data = bertlv.Append(data, 0x82, []byte{0, 0, 1, 0, 1})

	parsed, err := ParsePublicKey(RSA2048, bertlv.Append(nil, 0x7f49, data))
	if err != nil {
		t.Fatal(err)
	}

	key := parsed.(*rsa.PublicKey)
	if key.E != 65537 || !bytes.Equal(key.N.Bytes(), modulus) {
		t.Errorf("key = %v, want RSA-2048 with public exponent 65537", key)
	}
}

func TestParseRSA3072RejectsRSA2048Response(t *testing.T) {
	data := append([]byte{0x7f, 0x49, 0x82, 0x01, 0x09, 0x81, 0x82, 0x01, 0x00}, bytes.Repeat([]byte{0xab}, 256)...)
	data = append(data, 0x82, 0x03, 0x01, 0x00, 0x01)

	if _, err := ParsePublicKey(RSA3072, data); !errors.Is(err, ErrInvalidResponse) {
		t.Errorf("RSA-2048 response for RSA-3072 request = %v, want ErrInvalidResponse", err)
	}
}

func TestParseECCPublicKey(t *testing.T) {
	for _, tt := range []struct {
		name      string
		algorithm Algorithm
		curve     elliptic.Curve
	}{
		{name: "P-256", algorithm: ECCP256, curve: elliptic.P256()},
		{name: "P-384", algorithm: ECCP384, curve: elliptic.P384()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			point := generatorPoint(tt.curve)
			data := bertlv.Append(nil, 0x7f49, bertlv.Append(nil, 0x86, point))

			parsed, err := ParsePublicKey(tt.algorithm, data)
			if err != nil {
				t.Fatal(err)
			}

			key, ok := parsed.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("key type = %T, want *ecdsa.PublicKey", parsed)
			}

			encoded, err := key.Bytes()
			if err != nil {
				t.Fatal(err)
			}

			if key.Curve != tt.curve || !bytes.Equal(encoded, point) {
				t.Errorf("key = %v, want %s generator", key, tt.name)
			}
		})
	}
}

func TestParsePublicKeyRejectsInvalidResponse(t *testing.T) {
	modulus := bytes.Repeat([]byte{0xab}, 256)
	modulusTLV := bertlv.Append(nil, 0x81, modulus)
	exponentTLV := []byte{0x82, 0x03, 0x01, 0x00, 0x01}
	rsaData := append(bytes.Clone(modulusTLV), exponentTLV...)
	point := generatorPoint(elliptic.P256())
	pointTLV := bertlv.Append(nil, 0x86, point)
	encode := func(data []byte) []byte { return bertlv.Append(nil, 0x7f49, data) }

	tests := []struct {
		name      string
		algorithm Algorithm
		data      []byte
	}{
		{name: "wrong wrapper", algorithm: RSA2048, data: []byte{0x53, 0x00}},
		{name: "trailing bytes", algorithm: RSA2048, data: append(encode(rsaData), 0x00)},
		{name: "truncated field", algorithm: RSA2048, data: encode([]byte{0x81, 0x01})},
		{name: "unknown field", algorithm: RSA2048, data: encode(append(bytes.Clone(rsaData), 0x83, 0x00))},
		{name: "missing modulus", algorithm: RSA2048, data: encode(exponentTLV)},
		{name: "missing exponent", algorithm: RSA2048, data: encode(modulusTLV)},
		{name: "duplicate modulus", algorithm: RSA2048, data: encode(append(bytes.Clone(rsaData), modulusTLV...))},
		{name: "duplicate exponent", algorithm: RSA2048, data: encode(append(bytes.Clone(rsaData), exponentTLV...))},
		{name: "RSA size mismatch", algorithm: RSA1024, data: encode(rsaData)},
		{name: "RSA parameters for ECC", algorithm: ECCP256, data: encode(rsaData)},
		{name: "ECC point for RSA", algorithm: RSA2048, data: encode(pointTLV)},
		{name: "missing ECC point", algorithm: ECCP256, data: encode(nil)},
		{name: "duplicate point", algorithm: ECCP256, data: encode(append(bytes.Clone(pointTLV), pointTLV...))},
		{name: "curve mismatch", algorithm: ECCP384, data: encode(pointTLV)},
		{name: "point outside curve", algorithm: ECCP256, data: encode(bertlv.Append(nil, 0x86, append([]byte{0x04}, make([]byte, 64)...)))},
		{name: "compressed point", algorithm: ECCP256, data: encode(bertlv.Append(nil, 0x86, append([]byte{0x03}, point[1:33]...)))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePublicKey(tt.algorithm, tt.data)
			if !errors.Is(err, ErrInvalidResponse) {
				t.Errorf("error = %v, want ErrInvalidResponse", err)
			}
		})
	}

	for _, exponent := range [][]byte{nil, {0}, {1}, {2}, {4}, {0x80, 0, 0, 1}, {1, 0, 0, 0, 1}} {
		t.Run("invalid RSA exponent", func(t *testing.T) {
			data := bertlv.Append(bytes.Clone(modulusTLV), 0x82, exponent)

			_, err := ParsePublicKey(RSA2048, encode(data))
			if !errors.Is(err, ErrInvalidResponse) {
				t.Errorf("exponent %x: error = %v, want ErrInvalidResponse", exponent, err)
			}
		})
	}

	for _, firstLast := range [][2]byte{{0x7f, 0xab}, {0xab, 0xaa}} {
		t.Run("invalid RSA modulus", func(t *testing.T) {
			invalidModulus := bytes.Clone(modulus)
			invalidModulus[0], invalidModulus[len(invalidModulus)-1] = firstLast[0], firstLast[1]
			data := bertlv.Append(nil, 0x81, invalidModulus)
			data = append(data, exponentTLV...)

			_, err := ParsePublicKey(RSA2048, encode(data))
			if !errors.Is(err, ErrInvalidResponse) {
				t.Errorf("error = %v, want ErrInvalidResponse", err)
			}
		})
	}
}

func TestParsePublicKeyRejectsUnsupportedAlgorithm(t *testing.T) {
	if _, err := ParsePublicKey(Algorithm(0xff), []byte{0x7f, 0x49, 0x00}); err == nil {
		t.Fatal("expected unsupported algorithm error")
	}
}

func generatorPoint(curve elliptic.Curve) []byte {
	parameters := curve.Params()
	size := (parameters.BitSize + 7) / 8
	point := make([]byte, 1+2*size)
	point[0] = 4
	parameters.Gx.FillBytes(point[1 : 1+size])
	parameters.Gy.FillBytes(point[1+size:])

	return point
}
