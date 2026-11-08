package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestIrisImageRecordWire(t *testing.T) {
	// ISO/IEC 19794-6:2011 Tables 3-4: 16-byte header, one 52-byte
	// representation header plus a five-byte quality block and three image bytes.
	encoded := biometricHex(t, "49495200303230000000004c00010001"+
		"0000003c07e80102030405ffff0112342345015034564567"+
		"000102070a4501800100080100ffffffff00c000c00080008000a000a000000003aabbcc")

	parsed, err := ParseIrisImageRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.NumberOfEyes != 1 || len(parsed.Representations) != 1 {
		t.Fatalf("iris record = %+v", parsed)
	}

	iris := parsed.Representations[0]
	if iris.Number != 1 || iris.Eye != 2 || iris.CaptureTechnology != 1 || iris.CaptureVendor != 0x1234 || iris.CaptureType != 0x2345 || len(iris.Quality) != 1 || iris.Quality[0] != (BiometricQuality{Score: 80, Vendor: 0x3456, Algorithm: 0x4567}) || iris.Width != 384 || iris.Height != 256 || iris.RollAngle != 0xffff || iris.CenterXMinimum != 192 || !bytes.Equal(iris.Image, []byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("iris representation = %+v", iris)
	}

	if !bytes.Equal(EncodeIrisImageRecord(parsed), encoded) {
		t.Error("iris bytes differ from independent layout")
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
