package protocol

import (
	"bytes"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"fmt"

	"github.com/telesma-app/bertlv"
)

// DataGroupMapping associates an ICAO data group with a PIV container.
type DataGroupMapping struct {
	DataGroup   uint8
	ContainerID ContainerID
}

// SecurityObjectData is the Security Object's contents (Part 1, Table 13).
// Raw and SignedData borrow the parsed input. SignedData is the encoded CMS
// ContentInfo in tag BB; parsing this object does not authenticate it.
type SecurityObjectData struct {
	Raw        []byte
	Mapping    []DataGroupMapping
	SignedData []byte
}

// EncodeSecurityObject encodes BA, BB and an empty error detection code for
// PutData. SignedData is a caller-supplied CMS signature over an LDS object.
func EncodeSecurityObject(object SecurityObjectData) []byte {
	mapping := make([]byte, 0, 3*len(object.Mapping))
	for _, entry := range object.Mapping {
		mapping = append(mapping, entry.DataGroup)
		mapping = binary.BigEndian.AppendUint16(mapping, uint16(entry.ContainerID))
	}

	data := bertlv.Append(nil, 0xba, mapping)
	data = bertlv.Append(data, 0xbb, object.SignedData)

	return append(data, 0xfe, 0)
}

// ParseSecurityObject parses the object contents returned by GetData. Data
// groups must be unique in 1..16, and each container may occur only once.
func ParseSecurityObject(data []byte) (SecurityObjectData, error) {
	object := SecurityObjectData{Raw: data}

	var haveMapping, haveSignature, haveEDC bool

	for len(data) != 0 {
		tag, value, rest, err := bertlv.Parse(data)
		if err != nil {
			return SecurityObjectData{}, fmt.Errorf("%w: security object: %v", ErrInvalidResponse, err)
		}

		data = rest

		switch tag {
		case 0xba:
			if haveMapping || len(value)%3 != 0 || len(value) == 0 || len(value) > 30 {
				return SecurityObjectData{}, fmt.Errorf("%w: invalid data-group mapping", ErrInvalidResponse)
			}

			haveMapping = true

			var groups uint16

			for len(value) != 0 {
				entry := DataGroupMapping{DataGroup: value[0], ContainerID: ContainerID(binary.BigEndian.Uint16(value[1:3]))}
				if entry.DataGroup < 1 || entry.DataGroup > 16 || groups&(1<<(entry.DataGroup-1)) != 0 {
					return SecurityObjectData{}, fmt.Errorf("%w: invalid or duplicate data-group number", ErrInvalidResponse)
				}

				for _, previous := range object.Mapping {
					if entry.ContainerID == previous.ContainerID {
						return SecurityObjectData{}, fmt.Errorf("%w: duplicate data-group container", ErrInvalidResponse)
					}
				}

				groups |= 1 << (entry.DataGroup - 1)
				object.Mapping = append(object.Mapping, entry)
				value = value[3:]
			}
		case 0xbb:
			if haveSignature || len(value) == 0 {
				return SecurityObjectData{}, fmt.Errorf("%w: invalid security-object signature", ErrInvalidResponse)
			}

			haveSignature, object.SignedData = true, value
		case 0xfe:
			if haveEDC || len(value) != 0 {
				return SecurityObjectData{}, fmt.Errorf("%w: invalid security-object error detection code", ErrInvalidResponse)
			}

			haveEDC = true
		}
	}

	if !haveMapping || !haveSignature {
		return SecurityObjectData{}, fmt.Errorf("%w: incomplete security object", ErrInvalidResponse)
	}

	return object, nil
}

// DataGroupHash is one digest in an ICAO LDS Security Object.
type DataGroupHash struct {
	DataGroup uint8
	Digest    []byte
}

// LDSVersionInfo is present in version 1 LDS Security Objects.
type LDSVersionInfo struct {
	LDSVersion     string `asn1:"printable"`
	UnicodeVersion string `asn1:"printable"`
}

// LDSSecurityObject is the signed digest list in SecurityObjectData.SignedData
// (ICAO Doc 9303 Part 10, Sec. 4.6.2.3). Raw preserves the encoded signed bytes.
// ParseLDSSecurityObject does not authenticate them. HashAlgorithm is SHA-256
// or SHA-384, as required by SP 800-78-5, Sec. 3.2.3.
type LDSSecurityObject struct {
	Raw           []byte
	HashAlgorithm crypto.Hash
	Hashes        []DataGroupHash
	VersionInfo   *LDSVersionInfo
}

// EncodeLDSSecurityObject DER-encodes a digest list for CMS signing. A non-nil
// VersionInfo selects version 1; otherwise version 0 is encoded.
func EncodeLDSSecurityObject(object LDSSecurityObject) ([]byte, error) {
	var encoded ldsSecurityObject

	switch object.HashAlgorithm {
	case crypto.SHA256:
		encoded.HashAlgorithm.Algorithm = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	case crypto.SHA384:
		encoded.HashAlgorithm.Algorithm = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	default:
		return nil, fmt.Errorf("piv: unsupported LDS digest algorithm %v", object.HashAlgorithm)
	}

	if object.VersionInfo != nil {
		encoded.Version = 1

		versionInfo, err := asn1.Marshal(*object.VersionInfo)
		if err != nil {
			return nil, err
		}

		encoded.VersionInfo.FullBytes = versionInfo
	}

	for _, entry := range object.Hashes {
		encoded.Hashes = append(encoded.Hashes, ldsDataGroupHash{DataGroup: int(entry.DataGroup), Digest: entry.Digest})
	}

	return asn1.Marshal(encoded)
}

// ParseLDSSecurityObject parses a complete DER-encoded signed LDS digest list.
// Digests borrow the input; groups must be unique and within 1..16.
func ParseLDSSecurityObject(data []byte) (LDSSecurityObject, error) {
	var encoded ldsSecurityObject

	rest, err := asn1.Unmarshal(data, &encoded)
	if err != nil || len(rest) != 0 {
		return LDSSecurityObject{}, fmt.Errorf("%w: malformed LDS security object", ErrInvalidResponse)
	}

	canonical, err := asn1.Marshal(encoded)
	if err != nil || !bytes.Equal(canonical, data) {
		return LDSSecurityObject{}, fmt.Errorf("%w: noncanonical or extra LDS fields", ErrInvalidResponse)
	}

	if (encoded.Version != 0 && encoded.Version != 1) || (encoded.Version == 1) != (encoded.VersionInfo.FullBytes != nil) || len(encoded.Hashes) < 2 || len(encoded.Hashes) > 16 {
		return LDSSecurityObject{}, fmt.Errorf("%w: invalid LDS version or group count", ErrInvalidResponse)
	}

	object := LDSSecurityObject{Raw: data}
	if encoded.VersionInfo.FullBytes != nil {
		object.VersionInfo = new(LDSVersionInfo)

		rest, err := asn1.Unmarshal(encoded.VersionInfo.FullBytes, object.VersionInfo)
		if err != nil || len(rest) != 0 {
			return LDSSecurityObject{}, fmt.Errorf("%w: invalid LDS version information", ErrInvalidResponse)
		}

		canonical, err := asn1.Marshal(*object.VersionInfo)
		if err != nil || !bytes.Equal(canonical, encoded.VersionInfo.FullBytes) {
			return LDSSecurityObject{}, fmt.Errorf("%w: extra LDS version information", ErrInvalidResponse)
		}
	}

	switch {
	case encoded.HashAlgorithm.Algorithm.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}):
		object.HashAlgorithm = crypto.SHA256
	case encoded.HashAlgorithm.Algorithm.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}):
		object.HashAlgorithm = crypto.SHA384
	default:
		return LDSSecurityObject{}, fmt.Errorf("%w: unsupported LDS digest algorithm", ErrInvalidResponse)
	}

	if p := encoded.HashAlgorithm.Parameters.FullBytes; len(p) != 0 && string(p) != "\x05\x00" {
		return LDSSecurityObject{}, fmt.Errorf("%w: invalid LDS digest parameters", ErrInvalidResponse)
	}

	var groups uint16
	for _, entry := range encoded.Hashes {
		if entry.DataGroup < 1 || entry.DataGroup > 16 || groups&(1<<(entry.DataGroup-1)) != 0 || len(entry.Digest) != object.HashAlgorithm.Size() {
			return LDSSecurityObject{}, fmt.Errorf("%w: invalid LDS data-group digest", ErrInvalidResponse)
		}

		groups |= 1 << (entry.DataGroup - 1)
		object.Hashes = append(object.Hashes, DataGroupHash{DataGroup: uint8(entry.DataGroup), Digest: entry.Digest})
	}

	return object, nil
}

type ldsDataGroupHash struct {
	DataGroup int
	Digest    []byte
}

type ldsSecurityObject struct {
	Version       int
	HashAlgorithm pkix.AlgorithmIdentifier
	Hashes        []ldsDataGroupHash
	VersionInfo   asn1.RawValue `asn1:"optional"`
}
