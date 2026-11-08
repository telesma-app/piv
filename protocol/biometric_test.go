package protocol

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"
)

func biometricHex(t testing.TB, encoded string) []byte {
	t.Helper()

	data, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func TestBiometricDataGSAInteroperability(t *testing.T) {
	for _, tc := range []struct {
		name       string
		modality   BiometricType
		formatType uint16
		recordSize int
	}{
		{name: "fingerprints", modality: BiometricFingerprint, formatType: 0x0201, recordSize: 584},
		{name: "face", modality: BiometricFace, formatType: 0x0501, recordSize: 5444},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Public GSA Golden PIV Card 46 is an independent wire oracle.
			data, err := os.ReadFile("../testdata/gsa/card46-" + tc.name + ".bin")
			if err != nil {
				t.Fatal(err)
			}

			object, err := ParseBiometricData(data)
			if err != nil {
				t.Fatal(err)
			}

			if object.Header.BiometricType != tc.modality || object.Header.FormatOwner != 0x001b || object.Header.FormatType != tc.formatType || len(object.Record) != tc.recordSize || len(object.Signature) != 788 {
				t.Fatalf("biometric metadata = %+v, record = %d, signature = %d", object.Header, len(object.Record), len(object.Signature))
			}

			if string(bytes.TrimRight(object.Header.Creator[:], "\x00")) != "NIST Creator" || object.Header.ValidUntil != time.Date(2032, 12, 2, 0, 0, 0, 0, time.UTC) {
				t.Errorf("creator or expiry = %+v", object.Header)
			}

			if !bytes.Equal(object.SignedData[88:], object.Record) || !bytes.Equal(EncodeBiometricData(object), data) {
				t.Error("encoded biometric bytes differ from independent GSA data")
			}

			if &object.Raw[0] != &data[0] || &object.SignedData[0] != &data[4] || &object.Record[0] != &data[92] {
				t.Error("parsed biometric slices do not borrow input")
			}
		})
	}
}

func TestEncodeBiometricDataWire(t *testing.T) {
	date := time.Date(2005, 12, 15, 17, 35, 30, 0, time.UTC)
	object := BiometricData{
		Header: BiometricHeader{SecurityOptions: 0x0d, FormatOwner: 0x001b, FormatType: 0x0201, CreationDate: date, ValidFrom: date, ValidUntil: date, BiometricType: BiometricFingerprint, DataType: 0x80, Quality: -2},
		Record: []byte{0xaa, 0xbb}, Signature: []byte{0x30, 0x00},
	}
	// Header bytes follow SP 800-76-2 Table 14, including its example date.
	want := biometricHex(t, "bc5c030d000000020002001b020114050c0f11231e5a14050c0f11231e5a14050c0f11231e5a00000880fe"+
		"000000000000000000000000000000000000"+
		"00000000000000000000000000000000000000000000000000"+
		"00000000aabb3000fe00")

	got := EncodeBiometricData(object)
	if !bytes.Equal(got, want) {
		t.Fatalf("encoded biometric = %x, want %x", got, want)
	}

	parsed, err := ParseBiometricData(want)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.Header != object.Header || !bytes.Equal(parsed.Record, object.Record) || !bytes.Equal(parsed.Signature, object.Signature) {
		t.Errorf("parsed biometric = %+v", parsed)
	}
}

func TestParseBiometricDataRejectsMalformedExternalObjects(t *testing.T) {
	date := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	valid := EncodeBiometricData(BiometricData{Header: BiometricHeader{SecurityOptions: 0x0d, CreationDate: date, ValidFrom: date, ValidUntil: date}})

	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "duplicate BC", mutate: func(b []byte) []byte { return append(b, b...) }},
		{name: "invalid version", mutate: func(b []byte) []byte { b[2] = 4; return b }},
		{name: "unsupported options", mutate: func(b []byte) []byte { b[3] = 0; return b }},
		{name: "BDB length overflow", mutate: func(b []byte) []byte { b[4] = 0xff; return b }},
		{name: "signature length mismatch", mutate: func(b []byte) []byte { b[8] = 1; return b }},
		{name: "invalid date", mutate: func(b []byte) []byte { b[16] = 13; return b }},
		{name: "invalid timezone", mutate: func(b []byte) []byte { b[21] = 0; return b }},
		{name: "quality", mutate: func(b []byte) []byte { b[42] = 101; return b }},
		{name: "unterminated creator", mutate: func(b []byte) []byte {
			for i := 43; i < 61; i++ {
				b[i] = 'x'
			}

			return b
		}},
		{name: "reserved bytes", mutate: func(b []byte) []byte { b[86] = 1; return b }},
		{name: "nonempty EDC", mutate: func(b []byte) []byte { return append(b[:len(b)-1], 1, 0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseBiometricData(tc.mutate(bytes.Clone(valid)))
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("error = %v", err)
			}
		})
	}

	for end := range len(valid) - 2 {
		if _, err := ParseBiometricData(valid[:end]); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("prefix %d: error = %v", end, err)
		}
	}
}
