package protocol

import (
	"encoding/binary"
	"fmt"
)

// FingerPosition is the INCITS 378 finger position, not the BIT subtype code.
type FingerPosition byte

const (
	FingerUnspecified FingerPosition = iota
	FingerRightThumb
	FingerRightIndex
	FingerRightMiddle
	FingerRightRing
	FingerRightLittle
	FingerLeftThumb
	FingerLeftIndex
	FingerLeftMiddle
	FingerLeftRing
	FingerLeftLittle
)

// FingerprintRecord is an INCITS 378-2004 PIV fingerprint template, carried
// in BiometricData.Record (SP 800-76-2, Table 6). Dimensions are pixels;
// resolutions are pixels per centimeter. CaptureEquipment includes the
// high-nibble compliance flags and low twelve-bit capture equipment ID.
// Raw borrows the parsed biometric record.
type FingerprintRecord struct {
	Raw              []byte
	ProductOwner     uint16
	ProductType      uint16
	CaptureEquipment uint16
	Width, Height    uint16
	ResolutionX      uint16
	ResolutionY      uint16
	Views            []FingerprintView
}

// FingerprintView contains one finger's minutiae. Quality is a value from
// 0 through 100. The PIV profile uses 254 for permanently unusable fingerprints
// and 255 for temporarily unusable fingerprints.
type FingerprintView struct {
	Finger         FingerPosition
	ViewNumber     byte
	ImpressionType byte
	Quality        byte
	Minutiae       []FingerprintMinutia
}

// FingerprintMinutia is the six-byte INCITS 378 minutia. X and Y are pixel
// coordinates from the upper-left origin, each fitting fourteen bits. Angle
// runs counterclockwise in two-degree units and is in [0,179]. Quality is
// 0 when unavailable, or 1 through 100 with increasing confidence. The
// card-compact OCC representation is a different format.
type FingerprintMinutia struct {
	X, Y    uint16
	Type    MinutiaType
	Angle   byte
	Quality byte
}

// ParseFingerprintRecord parses the unencrypted INCITS 378-2004 PIV record.
// It accepts at most two views, including individual off-card probes. PIV
// enrollment records use two views, with empty minutiae lists for unavailable
// fingerprints. Extended data are forbidden by the PIV profile. It does not
// perform biometric comparison or evaluate the acquisition quality policy.
func ParseFingerprintRecord(data []byte) (FingerprintRecord, error) {
	if len(data) < 26 || string(data[:8]) != "FMR\x00 20\x00" || int(binary.BigEndian.Uint16(data[8:10])) != len(data) || data[24] > 2 || data[25] != 0 {
		return FingerprintRecord{}, fmt.Errorf("%w: PIV fingerprint record header", ErrInvalidResponse)
	}

	result := FingerprintRecord{
		Raw: data, ProductOwner: binary.BigEndian.Uint16(data[10:12]), ProductType: binary.BigEndian.Uint16(data[12:14]),
		CaptureEquipment: binary.BigEndian.Uint16(data[14:16]), Width: binary.BigEndian.Uint16(data[16:18]),
		Height: binary.BigEndian.Uint16(data[18:20]), ResolutionX: binary.BigEndian.Uint16(data[20:22]),
		ResolutionY: binary.BigEndian.Uint16(data[22:24]),
	}
	count := int(data[24])

	data = data[26:]
	for range count {
		if len(data) < 4 {
			return FingerprintRecord{}, fmt.Errorf("%w: fingerprint view header", ErrInvalidResponse)
		}

		view := FingerprintView{Finger: FingerPosition(data[0]), ViewNumber: data[1] >> 4, ImpressionType: data[1] & 0x0f, Quality: data[2]}

		minutiae := int(data[3])
		if view.Finger > FingerLeftLittle || !fingerprintViewQuality(view.Quality) || minutiae > 128 || len(data) < 4+6*minutiae+2 {
			return FingerprintRecord{}, fmt.Errorf("%w: fingerprint view", ErrInvalidResponse)
		}

		data = data[4:]
		for range minutiae {
			x, y := binary.BigEndian.Uint16(data[:2]), binary.BigEndian.Uint16(data[2:4])
			if x>>14 == 3 || y>>14 != 0 || data[4] > 179 || data[5] > 100 {
				return FingerprintRecord{}, fmt.Errorf("%w: fingerprint minutia", ErrInvalidResponse)
			}

			view.Minutiae = append(view.Minutiae, FingerprintMinutia{X: x & 0x3fff, Y: y, Type: MinutiaType(x >> 14), Angle: data[4], Quality: data[5]})
			data = data[6:]
		}

		if binary.BigEndian.Uint16(data[:2]) != 0 {
			return FingerprintRecord{}, fmt.Errorf("%w: PIV fingerprint extended data", ErrInvalidResponse)
		}

		data = data[2:]

		result.Views = append(result.Views, view)
	}

	if len(data) != 0 {
		return FingerprintRecord{}, fmt.Errorf("%w: trailing fingerprint record data", ErrInvalidResponse)
	}

	return result, nil
}

// EncodeFingerprintRecord encodes an INCITS 378-2004 record without the
// CBEFF or BC wrapper. Views and minutiae must follow the PIV profile's sizes
// and ranges; no extended data are generated.
func EncodeFingerprintRecord(record FingerprintRecord) []byte {
	data := make([]byte, 26)
	copy(data, "FMR\x00 20\x00")
	binary.BigEndian.PutUint16(data[10:12], record.ProductOwner)
	binary.BigEndian.PutUint16(data[12:14], record.ProductType)
	binary.BigEndian.PutUint16(data[14:16], record.CaptureEquipment)
	binary.BigEndian.PutUint16(data[16:18], record.Width)
	binary.BigEndian.PutUint16(data[18:20], record.Height)
	binary.BigEndian.PutUint16(data[20:22], record.ResolutionX)
	binary.BigEndian.PutUint16(data[22:24], record.ResolutionY)

	data[24] = byte(len(record.Views))
	for _, view := range record.Views {
		data = append(data, byte(view.Finger), view.ViewNumber<<4|view.ImpressionType, view.Quality, byte(len(view.Minutiae)))
		for _, minutia := range view.Minutiae {
			data = binary.BigEndian.AppendUint16(data, uint16(minutia.Type)<<14|minutia.X)
			data = binary.BigEndian.AppendUint16(data, minutia.Y)
			data = append(data, minutia.Angle, minutia.Quality)
		}

		data = append(data, 0, 0)
	}

	binary.BigEndian.PutUint16(data[8:10], uint16(len(data)))

	return data
}

func fingerprintViewQuality(quality byte) bool {
	return quality <= 100 || quality == 254 || quality == 255
}
