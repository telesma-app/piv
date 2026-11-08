package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
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

func TestFingerprintRecordRejectsMalformedExternalData(t *testing.T) {
	fingerprint := biometricHex(t, "464d5200203230000026000100028003020001e000c500c501000200500141230234403c0000")
	if _, err := ParseFingerprintRecord(fingerprint); err != nil {
		t.Fatalf("valid record: %v", err)
	}

	for end := range len(fingerprint) {
		if _, err := ParseFingerprintRecord(fingerprint[:end]); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("prefix %d: error = %v", end, err)
		}
	}

	if _, err := ParseFingerprintRecord(append(bytes.Clone(fingerprint), 0)); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("trailing byte: error = %v", err)
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

func TestFingerprintRecordRejectsMalformedViews(t *testing.T) {
	valid := biometricHex(t, "464d5200203230000026000100028003020001e000c500c501000200500141230234403c0000")
	if _, err := ParseFingerprintRecord(valid); err != nil {
		t.Fatalf("valid record: %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "missing view", mutate: func(b []byte) []byte { b[24] = 2; return b }},
		{name: "short view header", mutate: func(b []byte) []byte { return b[:29] }},
		{name: "invalid finger", mutate: func(b []byte) []byte { b[26] = 11; return b }},
		{name: "quality above maximum", mutate: func(b []byte) []byte { b[28] = 101; return b }},
		{name: "reserved quality", mutate: func(b []byte) []byte { b[28] = 253; return b }},
		{name: "minutia count exceeds view", mutate: func(b []byte) []byte { b[29] = 2; return b }},
		{name: "too many minutiae", mutate: func(b []byte) []byte {
			b[29] = 129
			b = append(b[:30], make([]byte, 6*129)...)

			return append(b, 0, 0)
		}},
		{name: "short minutia", mutate: func(b []byte) []byte { return b[:35] }},
		{name: "short extension length", mutate: func(b []byte) []byte { return b[:37] }},
		{name: "trailing view data", mutate: func(b []byte) []byte { return append(b, 0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := tc.mutate(bytes.Clone(valid))
			// Keep the record header valid so the parser reaches the malformed view.
			binary.BigEndian.PutUint16(bad[8:10], uint16(len(bad)))

			if _, err := ParseFingerprintRecord(bad); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("ParseFingerprintRecord = %v, want ErrInvalidResponse", err)
			}
		})
	}
}

func TestFingerprintRecordViewQuality(t *testing.T) {
	// One view without minutiae also represents an unavailable fingerprint.
	valid := biometricHex(t, "464d5200203230000020000100028003020001e000c500c50100020000000000")
	for _, tc := range []struct {
		name    string
		quality byte
	}{
		{name: "minimum", quality: 0},
		{name: "maximum", quality: 100},
		{name: "permanently unusable", quality: 254},
		{name: "temporarily unusable", quality: 255},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := bytes.Clone(valid)
			data[28] = tc.quality

			record, err := ParseFingerprintRecord(data)
			if err != nil {
				t.Fatal(err)
			}

			if len(record.Views) != 1 || record.Views[0].Quality != tc.quality || len(record.Views[0].Minutiae) != 0 {
				t.Errorf("fingerprint views = %+v, want quality %d and no minutiae", record.Views, tc.quality)
			}
		})
	}
}
