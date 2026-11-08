package protocol

import (
	"bytes"
	"compress/gzip"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/telesma-app/bertlv"
)

// The APDU response limit bounds compressed input, but not its expansion.
const maxCertificateSize = 1 << 20

// CertificateData contains the decoded certificate and optional legacy MSCUID
// from a PIV certificate object (SP 800-73-5 Part 1, Tables 11 and 16-40).
// MSCUID is retained for historic retired key-management certificates; new
// credentials no longer use it. Nil means absent; an empty non-nil slice means
// an explicitly empty field. Both fields borrow the parsed input, except DER
// is newly allocated when the certificate is GZIP-compressed.
// Parsing does not validate the X.509 contents or establish trust.
type CertificateData struct {
	DER    []byte
	MSCUID []byte
}

// EncodeCertificate encodes DER bytes as an uncompressed PIV certificate object
// value without its outer 0x53 wrapper (SP 800-73-5 Part 1, Tables 11 and 16-18).
func EncodeCertificate(der []byte) []byte {
	return EncodeCertificateData(CertificateData{DER: der})
}

// EncodeCertificateData encodes an uncompressed certificate object value,
// without its outer 53 template. A non-nil MSCUID emits the legacy tag 72;
// it is only applicable to historic retired certificates and is at most 38 bytes.
func EncodeCertificateData(certificate CertificateData) []byte {
	data := bertlv.Append(nil, 0x70, certificate.DER)
	data = append(data, 0x71, 1, 0)

	if certificate.MSCUID != nil {
		data = bertlv.Append(data, 0x72, certificate.MSCUID)
	}

	return append(data, 0xfe, 0)
}

// ParseCertificateData decodes a PIV certificate object value without its outer
// 53 template. It supports DER and GZIP-compressed certificates, preserves
// legacy MSCUID bytes, and does not parse the certificate's X.509 contents.
func ParseCertificateData(data []byte) (CertificateData, error) {
	certificate, _, err := decodeCertificate(data)
	return certificate, err
}

// DecodeCertificate extracts certificate bytes from the value of a PIV
// certificate data object, after removing its outer 0x53 wrapper. It supports
// uncompressed and GZIP-compressed data without parsing X.509.
// Uncompressed output borrows data; GZIP output is newly allocated.
func DecodeCertificate(data []byte) ([]byte, error) {
	certificate, _, err := decodeCertificate(data)
	return certificate.DER, err
}

func decodeCertificate(data []byte) (CertificateData, []byte, error) {
	var (
		certificate                           CertificateData
		intermediateCVC                       []byte
		info                                  byte
		haveCertificate, haveInfo, haveMSCUID bool
	)

	for len(data) > 0 {
		tag, value, rest, err := bertlv.Parse(data)
		if err != nil {
			return CertificateData{}, nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
		}

		switch tag {
		case 0x70:
			if haveCertificate {
				return CertificateData{}, nil, fmt.Errorf("%w: duplicate certificate", ErrInvalidResponse)
			}

			certificate.DER, haveCertificate = value, true
		case 0x71:
			if haveInfo || len(value) != 1 || value[0] > 1 {
				return CertificateData{}, nil, fmt.Errorf("%w: invalid certificate info", ErrInvalidResponse)
			}

			info, haveInfo = value[0], true
		case 0x72:
			if haveMSCUID || len(value) > 38 {
				return CertificateData{}, nil, fmt.Errorf("%w: invalid certificate MSCUID", ErrInvalidResponse)
			}

			certificate.MSCUID, haveMSCUID = value, true
		case 0x7f21:
			if intermediateCVC != nil {
				return CertificateData{}, nil, fmt.Errorf("%w: duplicate intermediate CVC", ErrInvalidResponse)
			}

			end := len(data) - len(rest)
			intermediateCVC = data[:end:end]
		case 0xfe:
			if len(value) != 0 {
				return CertificateData{}, nil, fmt.Errorf("%w: nonempty certificate error detection code", ErrInvalidResponse)
			}
		}

		data = rest
	}

	if !haveCertificate || !haveInfo {
		return CertificateData{}, nil, fmt.Errorf("%w: missing certificate or certificate info", ErrInvalidResponse)
	}

	// NIST SP 800-73-5 Part 1 specifies CertInfo 0x00 for DER and 0x01
	// for GZIP. Other bits are reserved or required to be zero for PIV.
	if info == 1 {
		reader, err := gzip.NewReader(bytes.NewReader(certificate.DER))
		if err != nil {
			return CertificateData{}, nil, fmt.Errorf("%w: certificate GZIP: %v", ErrInvalidResponse, err)
		}
		defer func() { _ = reader.Close() }()

		certificate.DER, err = io.ReadAll(io.LimitReader(reader, maxCertificateSize+1))
		if err != nil {
			return CertificateData{}, nil, fmt.Errorf("%w: certificate GZIP: %v", ErrInvalidResponse, err)
		}
	}

	if len(certificate.DER) > maxCertificateSize {
		return CertificateData{}, nil, fmt.Errorf("%w: certificate exceeds %d bytes", ErrInvalidResponse, maxCertificateSize)
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
