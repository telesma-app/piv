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
