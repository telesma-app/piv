package protocol

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

func TestFingerprintRecordWire(t *testing.T) {
	// INCITS 378-2004 header, one view, one six-byte minutia, no extensions.
	encoded := biometricHex(t, "464d5200203230000026000100028003020001e000c500c501000200500141230234403c0000")

	parsed, err := ParseFingerprintRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.ProductOwner != 1 || parsed.ProductType != 2 || parsed.CaptureEquipment != 0x8003 || parsed.Width != 512 || parsed.Height != 480 || parsed.ResolutionX != 197 || parsed.ResolutionY != 197 || len(parsed.Views) != 1 {
		t.Fatalf("fingerprint record = %+v", parsed)
	}

	view := parsed.Views[0]
	if view.Finger != FingerRightIndex || view.ViewNumber != 0 || view.ImpressionType != 0 || view.Quality != 80 || len(view.Minutiae) != 1 || view.Minutiae[0] != (FingerprintMinutia{X: 0x0123, Y: 0x0234, Type: MinutiaRidgeEnding, Angle: 64, Quality: 60}) {
		t.Errorf("fingerprint view = %+v", view)
	}

	if !bytes.Equal(EncodeFingerprintRecord(parsed), encoded) {
		t.Error("fingerprint encoded bytes differ from independent layout")
	}
}

func TestFingerprintRecordGSAInteroperability(t *testing.T) {
	data, err := os.ReadFile("../testdata/gsa/card46-fingerprints.bin")
	if err != nil {
		t.Fatal(err)
	}

	object, err := ParseBiometricData(data)
	if err != nil {
		t.Fatal(err)
	}

	record, err := ParseFingerprintRecord(object.Record)
	if err != nil {
		t.Fatal(err)
	}

	if record.ProductOwner != 1 || record.ProductType != 1 || record.CaptureEquipment != 0x8001 || record.Width != 512 || record.Height != 480 || len(record.Views) != 2 || record.Views[0].Finger != FingerLeftIndex || len(record.Views[0].Minutiae) != 41 {
		t.Fatalf("GSA fingerprint metadata = %+v", record)
	}

	if !bytes.Equal(EncodeFingerprintRecord(record), object.Record) {
		t.Error("GSA fingerprint round trip changed wire bytes")
	}
}

func TestFacialImageRecordWire(t *testing.T) {
	encoded := biometricHex(t, "4641430030313000000000390001"+
		"0000002b00010102030102030001010203040506"+
		"0121001000200000"+
		"010100c800a2010212340050aabbcc")

	parsed, err := ParseFacialImageRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if len(parsed.Images) != 1 {
		t.Fatalf("facial images = %+v", parsed.Images)
	}

	image := parsed.Images[0]
	if image.Gender != 1 || image.EyeColor != 2 || image.HairColor != 3 || image.FeatureMask != 0x010203 || image.Expression != 1 || image.PoseAngles != [3]byte{1, 2, 3} || image.PoseUncertainty != [3]byte{4, 5, 6} || len(image.FeaturePoints) != 1 || image.FeaturePoints[0] != (FacialFeaturePoint{Type: 1, Major: 2, Minor: 1, X: 16, Y: 32}) || image.Width != 200 || image.Height != 162 || image.DeviceType != 0x1234 || image.Quality != 80 || !bytes.Equal(image.Image, []byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("facial image = %+v", image)
	}

	if !bytes.Equal(EncodeFacialImageRecord(parsed), encoded) {
		t.Error("facial image bytes differ from independent layout")
	}
}

func TestFacialImageRecordGSAInteroperability(t *testing.T) {
	data, err := os.ReadFile("../testdata/gsa/card46-face.bin")
	if err != nil {
		t.Fatal(err)
	}

	object, err := ParseBiometricData(data)
	if err != nil {
		t.Fatal(err)
	}

	record, err := ParseFacialImageRecord(object.Record)
	if err != nil {
		t.Fatal(err)
	}

	if len(record.Images) != 1 {
		t.Fatalf("GSA face images = %d", len(record.Images))
	}

	image := record.Images[0]
	if image.Width != 200 || image.Height != 162 || image.ImageDataType != 1 || image.ImageType != 1 || image.ColorSpace != 1 || image.SourceType != 2 || len(image.Image) != 5398 {
		t.Fatalf("GSA facial metadata = %+v", image)
	}
	// JPEG2000 file signature is preserved, without an image decoder dependency.
	if !bytes.Equal(image.Image[:12], []byte{0, 0, 0, 12, 'j', 'P', ' ', ' ', 13, 10, 135, 10}) || !bytes.Equal(EncodeFacialImageRecord(record), object.Record) {
		t.Error("GSA face compressed image or metadata changed")
	}
}

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

func TestBiometricRecordsRejectMalformedExternalData(t *testing.T) {
	fingerprint := biometricHex(t, "464d5200203230000026000100028003020001e000c500c501000200500141230234403c0000")
	face := biometricHex(t, "46414300303130000000003100010000002300000000000000000001000000000000010100c800a2010212340050aabbcc")

	iris := biometricHex(t, "494952003032300000000047000100010000003707e80102030405ffff011234234500000102070a4501800100080100ffffffff00c000c00080008000a000a000000003aabbcc")
	for _, tc := range []struct {
		name  string
		valid []byte
		parse func([]byte) error
	}{
		{name: "fingerprint", valid: fingerprint, parse: func(b []byte) error { _, err := ParseFingerprintRecord(b); return err }},
		{name: "face", valid: face, parse: func(b []byte) error { _, err := ParseFacialImageRecord(b); return err }},
		{name: "iris", valid: iris, parse: func(b []byte) error { _, err := ParseIrisImageRecord(b); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.parse(tc.valid); err != nil {
				t.Fatalf("valid record: %v", err)
			}

			for end := range len(tc.valid) {
				if err := tc.parse(tc.valid[:end]); !errors.Is(err, ErrInvalidResponse) {
					t.Fatalf("prefix %d: error = %v", end, err)
				}
			}

			if err := tc.parse(append(bytes.Clone(tc.valid), 0)); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("trailing byte: error = %v", err)
			}
		})
	}
	// INCITS 378-2004 encodes angles in two-degree units, not the
	// 256-step angle used in ISO off-card records. NIST MINEX II, Table 23.
	badAngle := bytes.Clone(fingerprint)

	badAngle[34] = 180
	if _, err := ParseFingerprintRecord(badAngle); !errors.Is(err, ErrInvalidResponse) {
		t.Errorf("out-of-range ANSI minutia angle: %v", err)
	}

	// NIST MINEX II's INCITS 378 profile and BiomDI validate_fmd restrict
	// individual minutia quality to 0..100. PIV view-level 254/255 flags
	// do not apply to this field.
	for _, quality := range []byte{101, 254, 255} {
		bad := bytes.Clone(fingerprint)

		bad[35] = quality
		if _, err := ParseFingerprintRecord(bad); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("out-of-range minutia quality %d: %v", quality, err)
		}
	}

	for _, offset := range []int{30, 32, 37} {
		bad := bytes.Clone(fingerprint)

		bad[offset] = 0xff
		if _, err := ParseFingerprintRecord(bad); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("bad fingerprint at %d: %v", offset, err)
		}
	}
}
