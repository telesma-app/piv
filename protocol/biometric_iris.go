package protocol

import (
	"encoding/binary"
	"fmt"
)

// IrisImageRecord is an ISO/IEC 19794-6:2011 record, profiled for PIV in
// SP 800-76-2, Tables 9-10. NumberOfEyes is 0 when laterality is unknown,
// 1 for one known eye, or 2 for both eyes. Raw and images borrow parsed input.
type IrisImageRecord struct {
	Raw             []byte
	NumberOfEyes    byte
	Representations []IrisRepresentation
}

// IrisRepresentation describes one image without decoding its pixel payload.
// CaptureDate preserves ISO/IEC 19794-1's nine-byte timestamp, including unknown
// components and optional milliseconds. Dimensions, center and diameter limits
// are pixels. Range is camera-to-iris distance in mm (0 unassigned, 1 failed,
// FFFF overflow). RollAngle uses 65535 units per turn (FFFF unspecified);
// RollUncertainty uses 65535 units per half-turn (FFFF unspecified).
// ImageFormat is 02 raw monochrome, 0A JPEG2000, or 0E PNG.
// ImageProperties preserves the orientation and compression-history bitfield.
type IrisRepresentation struct {
	Raw               []byte
	CaptureDate       [9]byte
	CaptureTechnology byte
	CaptureVendor     uint16
	CaptureType       uint16
	Quality           []BiometricQuality
	Number            uint16
	Eye               byte
	ImageType         byte
	ImageFormat       byte
	ImageProperties   byte
	Width, Height     uint16
	BitDepth          byte
	Range             uint16
	RollAngle         uint16
	RollUncertainty   uint16
	CenterXMinimum    uint16
	CenterXMaximum    uint16
	CenterYMinimum    uint16
	CenterYMaximum    uint16
	DiameterMinimum   uint16
	DiameterMaximum   uint16
	Image             []byte
}

// BiometricQuality is an ISO/IEC 19794-1 quality block. Score is 0 through
// 100, or FF when computation failed. Vendor and Algorithm identify its source.
type BiometricQuality struct {
	Score     byte
	Vendor    uint16
	Algorithm uint16
}

// EncodeIrisImageRecord encodes ISO/IEC 19794-6:2011 metadata and opaque image
// bytes, without CBEFF or BC wrappers. Field values and counts must follow the
// standard's widths and the caller's PIV profile; encoding does not compress.
func EncodeIrisImageRecord(record IrisImageRecord) []byte {
	data := make([]byte, 16)
	copy(data, "IIR\x00020\x00")
	binary.BigEndian.PutUint16(data[12:14], uint16(len(record.Representations)))

	data[15] = record.NumberOfEyes
	for _, iris := range record.Representations {
		data = binary.BigEndian.AppendUint32(data, uint32(52+5*len(iris.Quality)+len(iris.Image)))
		data = append(data, iris.CaptureDate[:]...)
		data = append(data, iris.CaptureTechnology)
		data = binary.BigEndian.AppendUint16(data, iris.CaptureVendor)
		data = binary.BigEndian.AppendUint16(data, iris.CaptureType)

		data = append(data, byte(len(iris.Quality)))
		for _, quality := range iris.Quality {
			data = append(data, quality.Score)
			data = binary.BigEndian.AppendUint16(data, quality.Vendor)
			data = binary.BigEndian.AppendUint16(data, quality.Algorithm)
		}

		data = binary.BigEndian.AppendUint16(data, iris.Number)
		data = append(data, iris.Eye, iris.ImageType, iris.ImageFormat, iris.ImageProperties)
		data = binary.BigEndian.AppendUint16(data, iris.Width)
		data = binary.BigEndian.AppendUint16(data, iris.Height)
		data = append(data, iris.BitDepth)
		data = binary.BigEndian.AppendUint16(data, iris.Range)
		data = binary.BigEndian.AppendUint16(data, iris.RollAngle)
		data = binary.BigEndian.AppendUint16(data, iris.RollUncertainty)
		data = binary.BigEndian.AppendUint16(data, iris.CenterXMinimum)
		data = binary.BigEndian.AppendUint16(data, iris.CenterXMaximum)
		data = binary.BigEndian.AppendUint16(data, iris.CenterYMinimum)
		data = binary.BigEndian.AppendUint16(data, iris.CenterYMaximum)
		data = binary.BigEndian.AppendUint16(data, iris.DiameterMinimum)
		data = binary.BigEndian.AppendUint16(data, iris.DiameterMaximum)
		data = binary.BigEndian.AppendUint32(data, uint32(len(iris.Image)))
		data = append(data, iris.Image...)
	}

	binary.BigEndian.PutUint32(data[8:12], uint32(len(data)))

	return data
}

// ParseIrisImageRecord parses an unencrypted ISO/IEC 19794-6:2011 record from
// BiometricData.Record. Record, representation, quality and image lengths must
// agree exactly. The opaque image payload is not decoded or matched. It accepts
// the exceptional null-image enrollment representation in SP 800-76-2 Table 10.
func ParseIrisImageRecord(data []byte) (IrisImageRecord, error) {
	if len(data) < 16 || string(data[:8]) != "IIR\x00020\x00" || uint64(binary.BigEndian.Uint32(data[8:12])) != uint64(len(data)) || data[14] != 0 || data[15] > 2 {
		return IrisImageRecord{}, fmt.Errorf("%w: iris image record header", ErrInvalidResponse)
	}

	result := IrisImageRecord{Raw: data, NumberOfEyes: data[15]}

	count := int(binary.BigEndian.Uint16(data[12:14]))
	if count == 0 {
		return IrisImageRecord{}, fmt.Errorf("%w: empty iris image record", ErrInvalidResponse)
	}

	data = data[16:]
	for range count {
		if len(data) < 52 {
			return IrisImageRecord{}, fmt.Errorf("%w: iris representation header", ErrInvalidResponse)
		}

		length := uint64(binary.BigEndian.Uint32(data[:4]))
		qualityCount := int(data[18])

		headerLength := 52 + 5*qualityCount
		if length < uint64(headerLength) || length > uint64(len(data)) {
			return IrisImageRecord{}, fmt.Errorf("%w: iris representation length", ErrInvalidResponse)
		}

		block := data[:int(length)]
		iris := IrisRepresentation{Raw: block, CaptureDate: [9]byte(block[4:13]), CaptureTechnology: block[13], CaptureVendor: binary.BigEndian.Uint16(block[14:16]), CaptureType: binary.BigEndian.Uint16(block[16:18])}

		position := 19
		for range qualityCount {
			quality := block[position : position+5]
			if quality[0] > 100 && quality[0] != 255 {
				return IrisImageRecord{}, fmt.Errorf("%w: iris quality score", ErrInvalidResponse)
			}

			iris.Quality = append(iris.Quality, BiometricQuality{Score: quality[0], Vendor: binary.BigEndian.Uint16(quality[1:3]), Algorithm: binary.BigEndian.Uint16(quality[3:5])})
			position += 5
		}

		info := block[position:headerLength]
		iris.Number = binary.BigEndian.Uint16(info[:2])
		iris.Eye, iris.ImageType, iris.ImageFormat, iris.ImageProperties = info[2], info[3], info[4], info[5]
		iris.Width, iris.Height, iris.BitDepth = binary.BigEndian.Uint16(info[6:8]), binary.BigEndian.Uint16(info[8:10]), info[10]
		iris.Range = binary.BigEndian.Uint16(info[11:13])
		iris.RollAngle, iris.RollUncertainty = binary.BigEndian.Uint16(info[13:15]), binary.BigEndian.Uint16(info[15:17])
		iris.CenterXMinimum, iris.CenterXMaximum = binary.BigEndian.Uint16(info[17:19]), binary.BigEndian.Uint16(info[19:21])
		iris.CenterYMinimum, iris.CenterYMaximum = binary.BigEndian.Uint16(info[21:23]), binary.BigEndian.Uint16(info[23:25])
		iris.DiameterMinimum, iris.DiameterMaximum = binary.BigEndian.Uint16(info[25:27]), binary.BigEndian.Uint16(info[27:29])

		imageLength := uint64(binary.BigEndian.Uint32(info[29:33]))
		if imageLength != length-uint64(headerLength) || iris.Number == 0 || int(iris.Number) > count || iris.Eye > 2 {
			return IrisImageRecord{}, fmt.Errorf("%w: iris image metadata or length", ErrInvalidResponse)
		}

		iris.Image = block[headerLength:]
		result.Representations = append(result.Representations, iris)
		data = data[int(length):]
	}

	if len(data) != 0 {
		return IrisImageRecord{}, fmt.Errorf("%w: trailing iris image data", ErrInvalidResponse)
	}

	return result, nil
}
