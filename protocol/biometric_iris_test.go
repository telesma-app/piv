package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
)

func TestIrisImageRecordWire(t *testing.T) {
	// ISO/IEC 19794-6:2011 Tables 3-4: 16-byte header, one 52-byte
	// representation header plus a five-byte quality block and three image bytes.
	encoded := biometricHex(t, "49495200303230000000004c00010001"+
		"0000003c07e80102030405ffff0112342345015034564567"+
		"000102070a4501800100080100ffffffff00c000d00080009000a000b000000003aabbcc")
	want := IrisImageRecord{
		NumberOfEyes: 1,
		Representations: []IrisRepresentation{{
			CaptureDate:       [9]byte{0x07, 0xe8, 1, 2, 3, 4, 5, 0xff, 0xff},
			CaptureTechnology: 1, CaptureVendor: 0x1234, CaptureType: 0x2345,
			Quality: []BiometricQuality{{Score: 80, Vendor: 0x3456, Algorithm: 0x4567}},
			Number:  1, Eye: 2, ImageType: 7, ImageFormat: 0x0a, ImageProperties: 0x45,
			Width: 384, Height: 256, BitDepth: 8, Range: 256, RollAngle: 0xffff, RollUncertainty: 0xffff,
			CenterXMinimum: 192, CenterXMaximum: 208, CenterYMinimum: 128, CenterYMaximum: 144,
			DiameterMinimum: 160, DiameterMaximum: 176, Image: []byte{0xaa, 0xbb, 0xcc},
		}},
	}

	if got := EncodeIrisImageRecord(want); !bytes.Equal(got, encoded) {
		t.Errorf("iris bytes = %x, want %x", got, encoded)
	}

	parsed, err := ParseIrisImageRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if len(parsed.Representations) != 1 {
		t.Fatalf("iris representations = %d, want 1", len(parsed.Representations))
	}

	if !bytes.Equal(parsed.Raw, encoded) || !bytes.Equal(parsed.Representations[0].Raw, encoded[16:]) {
		t.Error("iris Raw fields differ from the encoded record and representation")
	}

	parsed.Raw, parsed.Representations[0].Raw = nil, nil

	if !reflect.DeepEqual(parsed, want) {
		t.Errorf("iris record = %+v, want %+v", parsed, want)
	}
}

func TestIrisImageRecordRejectsMalformedExternalData(t *testing.T) {
	iris := biometricHex(t, "494952003032300000000047000100010000003707e80102030405ffff011234234500000102070a4501800100080100ffffffff00c000c00080008000a000a000000003aabbcc")
	if _, err := ParseIrisImageRecord(iris); err != nil {
		t.Fatalf("valid record: %v", err)
	}

	for end := range len(iris) {
		if _, err := ParseIrisImageRecord(iris[:end]); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("prefix %d: error = %v", end, err)
		}
	}

	if _, err := ParseIrisImageRecord(append(bytes.Clone(iris), 0)); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("trailing byte: error = %v", err)
	}
}

func TestIrisImageRecordRejectsMalformedRepresentations(t *testing.T) {
	// One representation, one quality block, and three image bytes.
	valid := biometricHex(t, "49495200303230000000004c00010001"+
		"0000003c07e80102030405ffff0112342345015034564567"+
		"000102070a4501800100080100ffffffff00c000c00080008000a000a000000003aabbcc")
	if _, err := ParseIrisImageRecord(valid); err != nil {
		t.Fatalf("valid record: %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "no representations", mutate: func(b []byte) []byte { b[13] = 0; return b[:16] }},
		{name: "missing representation", mutate: func(b []byte) []byte { b[13] = 2; return b }},
		{name: "short representation header", mutate: func(b []byte) []byte { return b[:67] }},
		{name: "representation shorter than header", mutate: func(b []byte) []byte { b[19] = 51; return b }},
		{name: "representation shorter than quality blocks", mutate: func(b []byte) []byte { b[19] = 56; return b }},
		{name: "representation exceeds record", mutate: func(b []byte) []byte { b[19] = 61; return b }},
		{name: "quality count exceeds representation", mutate: func(b []byte) []byte { b[34] = 2; return b }},
		{name: "quality above maximum", mutate: func(b []byte) []byte { b[35] = 101; return b }},
		{name: "reserved quality", mutate: func(b []byte) []byte { b[35] = 254; return b }},
		{name: "zero representation number", mutate: func(b []byte) []byte { b[41] = 0; return b }},
		{name: "representation number exceeds count", mutate: func(b []byte) []byte { b[41] = 2; return b }},
		{name: "unknown eye", mutate: func(b []byte) []byte { b[42] = 3; return b }},
		{name: "image shorter than payload", mutate: func(b []byte) []byte { b[72] = 2; return b }},
		{name: "image exceeds payload", mutate: func(b []byte) []byte { b[72] = 4; return b }},
		{name: "trailing representation data", mutate: func(b []byte) []byte { return append(b, 0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := tc.mutate(bytes.Clone(valid))
			// Keep the record header valid so only the representation is malformed.
			binary.BigEndian.PutUint32(bad[8:12], uint32(len(bad)))

			if _, err := ParseIrisImageRecord(bad); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("ParseIrisImageRecord = %v, want ErrInvalidResponse", err)
			}
		})
	}
}

func TestIrisImageRecordAcceptsFailedQuality(t *testing.T) {
	encoded := biometricHex(t, "49495200303230000000004c00010001"+
		"0000003c07e80102030405ffff011234234501ff34564567"+
		"000102070a4501800100080100ffffffff00c000c00080008000a000a000000003aabbcc")

	parsed, err := ParseIrisImageRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if len(parsed.Representations) != 1 || len(parsed.Representations[0].Quality) != 1 || parsed.Representations[0].Quality[0].Score != 255 {
		t.Fatalf("failed quality score = %+v", parsed.Representations)
	}

	if !bytes.Equal(EncodeIrisImageRecord(parsed), encoded) {
		t.Error("failed quality score changed wire bytes")
	}
}

func TestIrisImageRecordAcceptsNullImageEnrollment(t *testing.T) {
	// A 16-byte record header and one 52-byte representation with no image.
	encoded := biometricHex(t, "49495200303230000000004400010000"+
		"00000034000000000000000000000000000000"+
		"000100000000000000000000000000000000000000000000000000000000000000")

	parsed, err := ParseIrisImageRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.NumberOfEyes != 0 || len(parsed.Representations) != 1 {
		t.Fatalf("null-image record = %+v", parsed)
	}

	iris := parsed.Representations[0]
	if iris.Number != 1 || iris.Eye != 0 || len(iris.Quality) != 0 || len(iris.Image) != 0 || iris.Width != 0 || iris.Height != 0 {
		t.Errorf("null-image representation = %+v", iris)
	}

	if !bytes.Equal(EncodeIrisImageRecord(parsed), encoded) {
		t.Error("null-image enrollment changed wire bytes")
	}
}
