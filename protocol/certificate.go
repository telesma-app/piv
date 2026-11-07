package protocol

import (
	"bytes"
	"compress/gzip"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/telesma-app/piv/internal/bertlv"
)

// The APDU response limit bounds compressed input, but not its expansion.
const maxCertificateSize = 1 << 20

// EncodeCertificate encodes DER bytes as an uncompressed PIV certificate object
// value without its outer 0x53 wrapper (SP 800-73-5 Part 1, Tables 11 and 16-18).
func EncodeCertificate(der []byte) []byte {
	data := bertlv.Append(nil, 0x70, der)
	return append(data, 0x71, 1, 0, 0xfe, 0)
}

// DecodeCertificate extracts certificate bytes from the value of a PIV
// certificate data object, after removing its outer 0x53 wrapper. It supports
// uncompressed and GZIP-compressed data without parsing X.509.
// Uncompressed output borrows data; GZIP output is newly allocated.
func DecodeCertificate(data []byte) ([]byte, error) {
	certificate, _, err := decodeCertificate(data)
	return certificate, err
}

func decodeCertificate(data []byte) ([]byte, []byte, error) {
	var (
		certificate, intermediateCVC []byte
		info                         byte
		haveCertificate, haveInfo    bool
	)

	for len(data) > 0 {
		tag, value, rest, err := bertlv.Parse(data)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
		}

		switch tag {
		case 0x70:
			if haveCertificate {
				return nil, nil, fmt.Errorf("%w: duplicate certificate", ErrInvalidResponse)
			}

			certificate, haveCertificate = value, true
		case 0x71:
			if haveInfo || len(value) != 1 || value[0] > 1 {
				return nil, nil, fmt.Errorf("%w: invalid certificate info", ErrInvalidResponse)
			}

			info, haveInfo = value[0], true
		case 0x7f21:
			if intermediateCVC != nil {
				return nil, nil, fmt.Errorf("%w: duplicate intermediate CVC", ErrInvalidResponse)
			}

			end := len(data) - len(rest)
			intermediateCVC = data[:end:end]
		case 0xfe:
			if len(value) != 0 {
				return nil, nil, fmt.Errorf("%w: nonempty certificate error detection code", ErrInvalidResponse)
			}
		}

		data = rest
	}

	if !haveCertificate || !haveInfo {
		return nil, nil, fmt.Errorf("%w: missing certificate or certificate info", ErrInvalidResponse)
	}

	// NIST SP 800-73-5 Part 1 specifies CertInfo 0x00 for DER and 0x01
	// for GZIP. Other bits are reserved or required to be zero for PIV.
	if info == 1 {
		reader, err := gzip.NewReader(bytes.NewReader(certificate))
		if err != nil {
			return nil, nil, fmt.Errorf("%w: certificate GZIP: %v", ErrInvalidResponse, err)
		}
		defer func() { _ = reader.Close() }()

		certificate, err = io.ReadAll(io.LimitReader(reader, maxCertificateSize+1))
		if err != nil {
			return nil, nil, fmt.Errorf("%w: certificate GZIP: %v", ErrInvalidResponse, err)
		}
	}

	if len(certificate) > maxCertificateSize {
		return nil, nil, fmt.Errorf("%w: certificate exceeds %d bytes", ErrInvalidResponse, maxCertificateSize)
	}

	return certificate, intermediateCVC, nil
}

// ParseCertificate parses the value of a PIV certificate data object, after
// removing its outer 0x53 wrapper. It supports DER and GZIP-compressed DER.
// It does not verify the certificate's signature.
func ParseCertificate(data []byte) (*x509.Certificate, error) {
	certificate, err := DecodeCertificate(data)
	if err != nil {
		return nil, err
	}

	parsed, err := x509.ParseCertificate(certificate)
	if err != nil {
		return nil, fmt.Errorf("%w: certificate DER: %v", ErrInvalidResponse, err)
	}

	return parsed, nil
}
