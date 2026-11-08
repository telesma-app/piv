package protocol

import (
	"fmt"
)

// OCCMinutia is one compact ISO/IEC 19794-2:2011 on-card comparison minutia.
// X and Y are in 0.1 mm units from the upper-left origin. Angle is measured
// counterclockwise in units of 360/64 degrees and must be in [0,63].
type OCCMinutia struct {
	X, Y  byte
	Type  MinutiaType
	Angle byte
}

// EncodeOCCMinutiae returns exactly 3N bytes for VerifyRequest.Data, without
// tags or a CBEFF header (SP 800-76-2, Sec. 5.5.2). It does not select, reorder,
// convert from off-card coordinates, or truncate minutiae; the producer follows
// the card's BiometricInformationTemplate parameters.
func EncodeOCCMinutiae(minutiae []OCCMinutia) []byte {
	data := make([]byte, 0, 3*len(minutiae))
	for _, minutia := range minutiae {
		data = append(data, minutia.X, minutia.Y, byte(minutia.Type)<<6|minutia.Angle)
	}

	return data
}

// ParseOCCMinutiae parses a compact on-card comparison probe, preserving its
// order. A reserved minutia type or a partial three-byte entry is rejected.
func ParseOCCMinutiae(data []byte) ([]OCCMinutia, error) {
	if len(data)%3 != 0 {
		return nil, fmt.Errorf("%w: OCC minutiae length", ErrInvalidResponse)
	}

	minutiae := make([]OCCMinutia, 0, len(data)/3)
	for len(data) != 0 {
		if data[2]>>6 == 3 {
			return nil, fmt.Errorf("%w: reserved OCC minutia type", ErrInvalidResponse)
		}

		minutiae = append(minutiae, OCCMinutia{X: data[0], Y: data[1], Type: MinutiaType(data[2] >> 6), Angle: data[2] & 0x3f})
		data = data[3:]
	}

	return minutiae, nil
}
