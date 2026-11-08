package protocol

import (
	"encoding/binary"
	"fmt"
)

// FacialImageRecord is the INCITS 385-2004 biometric record profiled by
// SP 800-76-2, Table 12. Raw and the image payloads borrow the parsed input.
// Parsing exposes metadata and feature points without decoding JPEG/JPEG2000.
type FacialImageRecord struct {
	Raw    []byte
	Images []FacialImage
}

// FacialImage contains the facial information, optional MPEG4 feature points,
// and image information preceding a compressed image. FeatureMask uses 24 bits.
// PoseAngles and PoseUncertainty retain the standard's encoded yaw/pitch/roll
// values; zero means unspecified. Dimensions and feature coordinates are pixels.
// ImageDataType is 0 for JPEG or 1 for JPEG2000.
type FacialImage struct {
	Raw             []byte
	Gender          byte
	EyeColor        byte
	HairColor       byte
	FeatureMask     uint32
	Expression      uint16
	PoseAngles      [3]byte
	PoseUncertainty [3]byte
	FeaturePoints   []FacialFeaturePoint
	ImageType       byte
	ImageDataType   byte
	Width, Height   uint16
	ColorSpace      byte
	SourceType      byte
	DeviceType      uint16
	Quality         uint16
	Image           []byte
}

// FacialFeaturePoint is an eight-byte feature point. Major and Minor are the
// four-bit MPEG4 point identifiers. Type 1 identifies a two-dimensional point.
type FacialFeaturePoint struct {
	Type         byte
	Major, Minor byte
	X, Y         uint16
}

// ParseFacialImageRecord parses an unencrypted INCITS 385-2004 record from
// BiometricData.Record. It checks framing, sizes, and reserved fields, without
// claiming that the image meets photographic capture or compression policy.
// The byte layout follows INCITS 385-2004 and NIST's BiomDI facerecognition
// reference implementation:
// https://github.com/usnistgov/biomdi/tree/master/facerecognition
func ParseFacialImageRecord(data []byte) (FacialImageRecord, error) {
	if len(data) < 14 || string(data[:8]) != "FAC\x00010\x00" || uint64(binary.BigEndian.Uint32(data[8:12])) != uint64(len(data)) {
		return FacialImageRecord{}, fmt.Errorf("%w: facial image record header", ErrInvalidResponse)
	}

	result := FacialImageRecord{Raw: data}

	count := int(binary.BigEndian.Uint16(data[12:14]))
	if count == 0 {
		return FacialImageRecord{}, fmt.Errorf("%w: empty facial image record", ErrInvalidResponse)
	}

	data = data[14:]
	for range count {
		if len(data) < 32 {
			return FacialImageRecord{}, fmt.Errorf("%w: facial image block header", ErrInvalidResponse)
		}

		length := uint64(binary.BigEndian.Uint32(data[:4]))
		points := int(binary.BigEndian.Uint16(data[4:6]))

		headerLength := 32 + 8*points
		if length < uint64(headerLength) || length > uint64(len(data)) {
			return FacialImageRecord{}, fmt.Errorf("%w: facial image block length", ErrInvalidResponse)
		}

		block := data[:int(length)]
		face := FacialImage{
			Raw: block, Gender: block[6], EyeColor: block[7], HairColor: block[8],
			FeatureMask: uint32(block[9])<<16 | uint32(block[10])<<8 | uint32(block[11]),
			Expression:  binary.BigEndian.Uint16(block[12:14]), PoseAngles: [3]byte(block[14:17]),
			PoseUncertainty: [3]byte(block[17:20]),
		}

		position := 20
		for range points {
			point := block[position : position+8]
			if point[6] != 0 || point[7] != 0 {
				return FacialImageRecord{}, fmt.Errorf("%w: facial feature reserved bytes", ErrInvalidResponse)
			}

			face.FeaturePoints = append(face.FeaturePoints, FacialFeaturePoint{Type: point[0], Major: point[1] >> 4, Minor: point[1] & 0x0f, X: binary.BigEndian.Uint16(point[2:4]), Y: binary.BigEndian.Uint16(point[4:6])})
			position += 8
		}

		info := block[position : position+12]
		face.ImageType, face.ImageDataType = info[0], info[1]
		face.Width, face.Height = binary.BigEndian.Uint16(info[2:4]), binary.BigEndian.Uint16(info[4:6])
		face.ColorSpace, face.SourceType = info[6], info[7]
		face.DeviceType, face.Quality = binary.BigEndian.Uint16(info[8:10]), binary.BigEndian.Uint16(info[10:12])
		face.Image = block[headerLength:]
		result.Images = append(result.Images, face)
		data = data[int(length):]
	}

	if len(data) != 0 {
		return FacialImageRecord{}, fmt.Errorf("%w: trailing facial image record data", ErrInvalidResponse)
	}

	return result, nil
}

// EncodeFacialImageRecord encodes the known INCITS 385-2004 fields without
// CBEFF or BC wrappers. It preserves compressed Image bytes; all field values
// and counts must fit the standard's widths and follow the caller's PIV profile.
func EncodeFacialImageRecord(record FacialImageRecord) []byte {
	data := make([]byte, 14)
	copy(data, "FAC\x00010\x00")
	binary.BigEndian.PutUint16(data[12:14], uint16(len(record.Images)))

	for _, face := range record.Images {
		block := make([]byte, 20)
		binary.BigEndian.PutUint32(block[:4], uint32(32+8*len(face.FeaturePoints)+len(face.Image)))
		binary.BigEndian.PutUint16(block[4:6], uint16(len(face.FeaturePoints)))
		block[6], block[7], block[8] = face.Gender, face.EyeColor, face.HairColor
		block[9], block[10], block[11] = byte(face.FeatureMask>>16), byte(face.FeatureMask>>8), byte(face.FeatureMask)
		binary.BigEndian.PutUint16(block[12:14], face.Expression)
		copy(block[14:17], face.PoseAngles[:])
		copy(block[17:20], face.PoseUncertainty[:])

		data = append(data, block...)
		for _, point := range face.FeaturePoints {
			data = append(data, point.Type, point.Major<<4|point.Minor)
			data = binary.BigEndian.AppendUint16(data, point.X)
			data = binary.BigEndian.AppendUint16(data, point.Y)
			data = append(data, 0, 0)
		}

		data = append(data, face.ImageType, face.ImageDataType)
		data = binary.BigEndian.AppendUint16(data, face.Width)
		data = binary.BigEndian.AppendUint16(data, face.Height)
		data = append(data, face.ColorSpace, face.SourceType)
		data = binary.BigEndian.AppendUint16(data, face.DeviceType)
		data = binary.BigEndian.AppendUint16(data, face.Quality)
		data = append(data, face.Image...)
	}

	binary.BigEndian.PutUint32(data[8:12], uint32(len(data)))

	return data
}
