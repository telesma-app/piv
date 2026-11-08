package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/telesma-app/bertlv"
)

// BiometricType is the three-byte CBEFF modality identifier.
type BiometricType uint32

const (
	BiometricFace        BiometricType = 0x000002
	BiometricFingerprint BiometricType = 0x000008
	BiometricIris        BiometricType = 0x000010
)

// BiometricHeader is the 88-byte PIV CBEFF header (SP 800-76-2, Table 14).
// SecurityOptions is 0D for signed data or 0F for signed and encrypted data.
// DataType retains all processing flags; Quality is -2 (unsupported), -1
// (failed), or 0 through 100. Creator contains a NUL-terminated ASCII name.
// Times are UTC instants with second precision. Parsing does not evaluate
// whether the validity period includes the current time.
type BiometricHeader struct {
	SecurityOptions byte
	FormatOwner     uint16
	FormatType      uint16
	CreationDate    time.Time
	ValidFrom       time.Time
	ValidUntil      time.Time
	BiometricType   BiometricType
	DataType        byte
	Quality         int8
	Creator         [18]byte
	FASCN           [25]byte
}

// BiometricData is a fingerprints, facial image, or iris images object.
// Record holds the complete encoded biometric data block, including its own
// format header. Image compression and encryption remain opaque. Signature is
// the detached CMS signature, not an indication that its signer is trusted.
// All byte slices borrow the parsed input. Raw preserves the complete object
// contents; SignedData preserves the exact CBEFF header and record bytes signed
// by Signature. Re-encoding a modified header or record invalidates that signature.
type BiometricData struct {
	Raw        []byte
	SignedData []byte
	Header     BiometricHeader
	Record     []byte
	Signature  []byte
}

// ParseBiometricData parses object contents without the outer 53 template
// (SP 800-73-5 Part 1, Tables 12, 14, and 41). The BC field contains the CBEFF
// concatenation defined by SP 800-76-2, Tables 13-15. It does not verify CMS
// signatures or decompress, decrypt, or match biometric records.
func ParseBiometricData(data []byte) (BiometricData, error) {
	result := BiometricData{Raw: data}

	var (
		encoded []byte
		haveEDC bool
	)

	for len(data) != 0 {
		tag, value, rest, err := bertlv.Parse(data)
		if err != nil {
			return BiometricData{}, fmt.Errorf("%w: biometric object: %v", ErrInvalidResponse, err)
		}

		data = rest

		switch tag {
		case 0xbc:
			if encoded != nil {
				return BiometricData{}, fmt.Errorf("%w: duplicate biometric record", ErrInvalidResponse)
			}

			encoded = value
		case 0xfe:
			if haveEDC || len(value) != 0 {
				return BiometricData{}, fmt.Errorf("%w: biometric error detection code", ErrInvalidResponse)
			}

			haveEDC = true
		}
	}

	if len(encoded) < 88 || encoded[0] != 3 || (encoded[1] != 0x0d && encoded[1] != 0x0f) {
		return BiometricData{}, fmt.Errorf("%w: invalid PIV CBEFF header", ErrInvalidResponse)
	}

	bdbLength := uint64(binary.BigEndian.Uint32(encoded[2:6]))

	signatureLength := uint64(binary.BigEndian.Uint16(encoded[6:8]))
	if 88+bdbLength+signatureLength != uint64(len(encoded)) {
		return BiometricData{}, fmt.Errorf("%w: CBEFF record length", ErrInvalidResponse)
	}

	header := BiometricHeader{
		SecurityOptions: encoded[1], FormatOwner: binary.BigEndian.Uint16(encoded[8:10]),
		FormatType:    binary.BigEndian.Uint16(encoded[10:12]),
		BiometricType: BiometricType(encoded[36])<<16 | BiometricType(encoded[37])<<8 | BiometricType(encoded[38]),
		DataType:      encoded[39], Quality: int8(encoded[40]),
		Creator: [18]byte(encoded[41:59]), FASCN: [25]byte(encoded[59:84]),
	}

	var err error
	if header.CreationDate, err = parseBiometricDate(encoded[12:20]); err != nil {
		return BiometricData{}, err
	}

	if header.ValidFrom, err = parseBiometricDate(encoded[20:28]); err != nil {
		return BiometricData{}, err
	}

	if header.ValidUntil, err = parseBiometricDate(encoded[28:36]); err != nil {
		return BiometricData{}, err
	}

	if header.ValidFrom.Before(header.CreationDate) || header.ValidUntil.Before(header.ValidFrom) {
		return BiometricData{}, fmt.Errorf("%w: CBEFF validity period", ErrInvalidResponse)
	}

	if header.Quality < -2 || header.Quality > 100 || !bytes.Equal(encoded[84:88], []byte{0, 0, 0, 0}) {
		return BiometricData{}, fmt.Errorf("%w: CBEFF quality or reserved bytes", ErrInvalidResponse)
	}

	terminator := bytes.IndexByte(header.Creator[:], 0)
	if terminator < 0 {
		return BiometricData{}, fmt.Errorf("%w: CBEFF creator terminator", ErrInvalidResponse)
	}

	for _, b := range header.Creator[:terminator] {
		if b < 0x20 || b > 0x7e {
			return BiometricData{}, fmt.Errorf("%w: CBEFF creator text", ErrInvalidResponse)
		}
	}

	end := 88 + int(bdbLength)
	result.Header, result.SignedData = header, encoded[:end]
	result.Record, result.Signature = encoded[88:end], encoded[end:]

	return result, nil
}

// EncodeBiometricData encodes the known BC and FE fields for PutData. Header
// lengths are derived from Record and Signature. The caller supplies a header
// and signature for exactly those bytes; encoding does not sign the record.
// Signature must fit its two-byte field and Record its four-byte field.
func EncodeBiometricData(data BiometricData) []byte {
	encoded := make([]byte, 88, 88+len(data.Record)+len(data.Signature))
	encoded[0], encoded[1] = 3, data.Header.SecurityOptions
	binary.BigEndian.PutUint32(encoded[2:6], uint32(len(data.Record)))
	binary.BigEndian.PutUint16(encoded[6:8], uint16(len(data.Signature)))
	binary.BigEndian.PutUint16(encoded[8:10], data.Header.FormatOwner)
	binary.BigEndian.PutUint16(encoded[10:12], data.Header.FormatType)
	encodeBiometricDate(encoded[12:20], data.Header.CreationDate)
	encodeBiometricDate(encoded[20:28], data.Header.ValidFrom)
	encodeBiometricDate(encoded[28:36], data.Header.ValidUntil)
	encoded[36], encoded[37], encoded[38] = byte(data.Header.BiometricType>>16), byte(data.Header.BiometricType>>8), byte(data.Header.BiometricType)
	encoded[39], encoded[40] = data.Header.DataType, byte(data.Header.Quality)
	copy(encoded[41:59], data.Header.Creator[:])
	copy(encoded[59:84], data.Header.FASCN[:])
	encoded = append(encoded, data.Record...)
	encoded = append(encoded, data.Signature...)

	return bertlv.Append(bertlv.Append(nil, 0xbc, encoded), 0xfe, nil)
}

func parseBiometricDate(data []byte) (time.Time, error) {
	year := int(data[0])*100 + int(data[1])

	date := time.Date(year, time.Month(data[2]), int(data[3]), int(data[4]), int(data[5]), int(data[6]), 0, time.UTC)
	if data[0] > 99 || data[1] > 99 || data[7] != 'Z' || date.Year() != year || byte(date.Month()) != data[2] || byte(date.Day()) != data[3] || byte(date.Hour()) != data[4] || byte(date.Minute()) != data[5] || byte(date.Second()) != data[6] {
		return time.Time{}, fmt.Errorf("%w: CBEFF date", ErrInvalidResponse)
	}

	return date, nil
}

func encodeBiometricDate(data []byte, value time.Time) {
	value = value.UTC()
	data[0], data[1] = byte(value.Year()/100), byte(value.Year()%100)
	data[2], data[3], data[4], data[5], data[6], data[7] = byte(value.Month()), byte(value.Day()), byte(value.Hour()), byte(value.Minute()), byte(value.Second()), 'Z'
}
