package protocol

import (
	"encoding/asn1"
	"fmt"
)

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
// Retrieval and verification of the file's URL hash belong to the caller.
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
