package protocol

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

func certificateDER(t testing.TB) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "PIV test certificate"},
		NotBefore:    time.Unix(1700000000, 0),
		NotAfter:     time.Unix(1800000000, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	return der
}

func certificateGZIP(t testing.TB, value []byte) []byte {
	t.Helper()

	var buffer bytes.Buffer

	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(value); err != nil {
		t.Fatal(err)
	}

	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	return buffer.Bytes()
}

func certificateObject(value []byte, info byte) []byte {
	data := append([]byte{0x70, 0x82, byte(len(value) >> 8), byte(len(value))}, value...)
	return append(data, 0x71, 1, info, 0xfe, 0)
}

func TestEncodeCertificateWire(t *testing.T) {
	for _, tc := range []struct {
		name   string
		der    []byte
		header []byte
	}{
		{name: "short", der: []byte{0x30, 0}, header: []byte{0x70, 2}},
		{name: "last short length", der: bytes.Repeat([]byte{0xab}, 127), header: []byte{0x70, 0x7f}},
		{name: "long length", der: bytes.Repeat([]byte{0xab}, 128), header: []byte{0x70, 0x81, 0x80}},
		{name: "two-byte length", der: bytes.Repeat([]byte{0xab}, 256), header: []byte{0x70, 0x82, 1, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := append(tc.header, tc.der...)
			want = append(want, 0x71, 1, 0, 0xfe, 0)

			got := EncodeCertificate(tc.der)

			if !bytes.Equal(got, want) {
				t.Errorf("certificate object = %x, want %x", got, want)
			}
		})
	}
}

func TestEncodeCertificatePreservesCertificate(t *testing.T) {
	der := certificateDER(t)

	data := EncodeCertificate(der)

	decoded, err := DecodeCertificate(data)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decoded, der) {
		t.Error("decoded certificate differs from the original DER")
	}

	parsed, err := ParseCertificate(data)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(parsed.Raw, der) || parsed.Subject.CommonName != "PIV test certificate" {
		t.Errorf("parsed a different certificate: %+v", parsed.Subject)
	}
}

func TestParseCertificate(t *testing.T) {
	der := certificateDER(t)
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "DER", data: certificateObject(der, 0)},
		{name: "GZIP", data: certificateObject(certificateGZIP(t, der), 1)},
		{name: "optional MSCUID", data: append(certificateObject(der, 0), 0x72, 1, 0x42)},
	} {
		t.Run(test.name, func(t *testing.T) {
			certificate, err := ParseCertificate(test.data)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(certificate.Raw, der) || certificate.Subject.CommonName != "PIV test certificate" {
				t.Errorf("parsed a different certificate: %+v", certificate.Subject)
			}
		})
	}
}

func TestDecodeCertificateWithoutX509Parsing(t *testing.T) {
	opaque := []byte{1, 2, 3}
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "uncompressed", data: certificateObject(opaque, 0)},
		{name: "GZIP", data: certificateObject(certificateGZIP(t, opaque), 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := DecodeCertificate(test.data)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(got, opaque) {
				t.Errorf("certificate bytes = %x, want %x", got, opaque)
			}

			if _, err := ParseCertificate(test.data); !errors.Is(err, ErrInvalidResponse) {
				t.Errorf("ParseCertificate error = %v, want invalid X.509", err)
			}
		})
	}
}

func TestDecodeCertificateBorrowsUncompressedData(t *testing.T) {
	data := certificateObject([]byte{1, 2, 3}, 0)

	got, err := DecodeCertificate(data)
	if err != nil {
		t.Fatal(err)
	}

	got[0] = 4

	if data[4] != 4 {
		t.Error("uncompressed certificate bytes do not borrow input")
	}

	if cap(got) != len(got) {
		t.Error("appending to certificate bytes could overwrite another field")
	}
}

func TestDecodeCertificateRejectsOversizedUncompressedData(t *testing.T) {
	data := append([]byte{0x70, 0x83, 0x10, 0x00, 0x01}, make([]byte, maxCertificateSize+1)...)
	data = append(data, 0x71, 1, 0, 0xfe, 0)

	if _, err := DecodeCertificate(data); !errors.Is(err, ErrInvalidResponse) {
		t.Errorf("DecodeCertificate error = %v, want ErrInvalidResponse", err)
	}
}

func TestParseCertificateInvalid(t *testing.T) {
	der := certificateDER(t)
	badChecksum := certificateGZIP(t, der)

	badChecksum[len(badChecksum)-8] ^= 1
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "missing certificate", data: []byte{0x71, 1, 0}},
		{name: "missing info", data: []byte{0x70, 1, 0}},
		{name: "duplicate certificate", data: append(certificateObject(der, 0), 0x70, 0)},
		{name: "duplicate info", data: append(certificateObject(der, 0), 0x71, 1, 0)},
		{name: "invalid info length", data: []byte{0x70, 0, 0x71, 0}},
		{name: "reserved info bit", data: certificateObject(der, 2)},
		{name: "nonempty error detection code", data: append(certificateObject(der, 0), 0xfe, 1, 0)},
		{name: "invalid DER", data: certificateObject([]byte{0x30, 0}, 0)},
		{name: "invalid GZIP header", data: certificateObject(der, 1)},
		{name: "invalid GZIP checksum", data: certificateObject(badChecksum, 1)},
		{name: "excessive expansion", data: certificateObject(certificateGZIP(t, bytes.Repeat([]byte{0}, maxCertificateSize+1)), 1)},
		{name: "malformed object", data: []byte{0x70, 0x82, 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseCertificate(test.data); !errors.Is(err, ErrInvalidResponse) {
				t.Errorf("ParseCertificate error = %v, want ErrInvalidResponse", err)
			}
		})
	}
}
