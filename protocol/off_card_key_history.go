package protocol

import (
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// ParseOffCardCertURL extracts the SHA-256 digest from the Key History object's
// offCardCertURL (SP 800-73-5 Part 1, Sec. 3.3.3 and Table 20). The URL must be
// http://<DNS name>/<64 ASCII hexadecimal digits>, within the field's 118-byte
// limit. This does not authenticate the URL or retrieve its contents.
func ParseOffCardCertURL(value string) ([32]byte, error) {
	var digest [32]byte

	scheme, address, ok := strings.Cut(value, "://")
	if !ok || !strings.EqualFold(scheme, "http") || len(value) > 118 {
		return digest, fmt.Errorf("%w: invalid off-card certificate URL", ErrInvalidResponse)
	}

	host, encoded, ok := strings.Cut(address, "/")
	if !ok || host == "" || len(encoded) != hex.EncodedLen(len(digest)) {
		return digest, fmt.Errorf("%w: invalid off-card certificate URL", ErrInvalidResponse)
	}

	name := strings.TrimSuffix(host, ".")
	if net.ParseIP(name) != nil {
		return digest, fmt.Errorf("%w: off-card certificate URL requires a DNS name", ErrInvalidResponse)
	}

	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || label[0] == '-' || label[len(label)-1] == '-' {
			return digest, fmt.Errorf("%w: invalid off-card certificate DNS name", ErrInvalidResponse)
		}

		for _, b := range []byte(label) {
			if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' {
				continue
			}

			return digest, fmt.Errorf("%w: invalid off-card certificate DNS name", ErrInvalidResponse)
		}
	}

	if _, err := hex.Decode(digest[:], []byte(encoded)); err != nil {
		return [32]byte{}, fmt.Errorf("%w: invalid off-card certificate SHA-256 digest: %v", ErrInvalidResponse, err)
	}

	return digest, nil
}

// OffCardCertificate associates a retired key reference with its certificate.
// DER contains the complete certificate SEQUENCE and borrows the parsed file.
type OffCardCertificate struct {
	Key KeyReference
	DER []byte
}

// ParseOffCardKeyHistoryFile parses the DER file identified by OffCardCertURL
// (SP 800-73-5 Part 1, Sec. 3.3.3). Entries retain their file order and must have
// distinct retired key references. The parser checks the file schema and DER
// framing without parsing X.509 contents.
// Retrieval and verification of the URL's SHA-256 digest are separate from
// parsing. ParseOffCardCertURL extracts the expected digest; the credential
// package verifies it against the retrieved file.
func ParseOffCardKeyHistoryFile(data []byte) ([]OffCardCertificate, error) {
	file, rest, err := offCardSequence(data)
	if err != nil {
		return nil, err
	}

	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: trailing off-card key history data", ErrInvalidResponse)
	}

	var (
		certificates []OffCardCertificate
		seen         uint32
	)

	for contents := file.Bytes; len(contents) != 0; {
		if len(certificates) == 20 {
			return nil, fmt.Errorf("%w: off-card key history exceeds 20 certificates", ErrInvalidResponse)
		}

		entry, rest, err := offCardSequence(contents)
		if err != nil {
			return nil, err
		}

		contents = rest

		var reference []byte

		rest, err = asn1.Unmarshal(entry.Bytes, &reference)
		if err != nil || len(reference) != 1 {
			return nil, fmt.Errorf("%w: invalid off-card key reference", ErrInvalidResponse)
		}

		key := KeyReference(reference[0])
		if key < RetiredKey1 || key > RetiredKey20 {
			return nil, fmt.Errorf("%w: off-card key reference %02x is not retired", ErrInvalidResponse, byte(key))
		}

		mask := uint32(1) << (key - RetiredKey1)
		if seen&mask != 0 {
			return nil, fmt.Errorf("%w: duplicate off-card key reference %02x", ErrInvalidResponse, byte(key))
		}

		seen |= mask

		certificate, rest, err := offCardSequence(rest)
		if err != nil {
			return nil, err
		}

		if len(rest) != 0 {
			return nil, fmt.Errorf("%w: trailing off-card certificate entry data", ErrInvalidResponse)
		}

		certificates = append(certificates, OffCardCertificate{Key: key, DER: certificate.FullBytes})
	}

	if len(certificates) == 0 {
		return nil, fmt.Errorf("%w: empty off-card key history", ErrInvalidResponse)
	}

	return certificates, nil
}

func offCardSequence(data []byte) (asn1.RawValue, []byte, error) {
	var sequence asn1.RawValue

	rest, err := asn1.Unmarshal(data, &sequence)
	if err != nil {
		return asn1.RawValue{}, nil, fmt.Errorf("%w: off-card key history DER: %v", ErrInvalidResponse, err)
	}

	if sequence.Class != asn1.ClassUniversal || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
		return asn1.RawValue{}, nil, fmt.Errorf("%w: off-card key history requires a SEQUENCE", ErrInvalidResponse)
	}

	return sequence, rest, nil
}
