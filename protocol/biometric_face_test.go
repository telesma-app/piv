package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

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

func TestFacialImageRecordRejectsMalformedExternalData(t *testing.T) {
	face := biometricHex(t, "46414300303130000000003100010000002300000000000000000001000000000000010100c800a2010212340050aabbcc")
	if _, err := ParseFacialImageRecord(face); err != nil {
		t.Fatalf("valid record: %v", err)
	}

	for end := range len(face) {
		if _, err := ParseFacialImageRecord(face[:end]); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("prefix %d: error = %v", end, err)
		}
	}

	if _, err := ParseFacialImageRecord(append(bytes.Clone(face), 0)); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("trailing byte: error = %v", err)
	}
}

func TestFacialImageRecordRejectsMalformedBlocks(t *testing.T) {
	// One image with one feature point and three opaque image bytes.
	valid := biometricHex(t, "4641430030313000000000390001"+
		"0000002b00010102030102030001010203040506"+
		"0121001000200000"+
		"010100c800a2010212340050aabbcc")
	if _, err := ParseFacialImageRecord(valid); err != nil {
		t.Fatalf("valid record: %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "no images", mutate: func(b []byte) []byte { b[13] = 0; return b[:14] }},
		{name: "missing image", mutate: func(b []byte) []byte { b[13] = 2; return b }},
		{name: "short block header", mutate: func(b []byte) []byte { return b[:45] }},
		{name: "block shorter than header", mutate: func(b []byte) []byte { b[17] = 31; return b }},
		{name: "block shorter than feature points", mutate: func(b []byte) []byte { b[17] = 39; return b }},
		{name: "block exceeds record", mutate: func(b []byte) []byte { b[17] = 44; return b }},
		{name: "feature count exceeds block", mutate: func(b []byte) []byte { b[19] = 2; return b }},
		{name: "first reserved feature byte", mutate: func(b []byte) []byte { b[40] = 1; return b }},
		{name: "second reserved feature byte", mutate: func(b []byte) []byte { b[41] = 1; return b }},
		{name: "trailing block data", mutate: func(b []byte) []byte { return append(b, 0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := tc.mutate(bytes.Clone(valid))
			// Keep the record header valid so only the inner block is malformed.
			binary.BigEndian.PutUint32(bad[8:12], uint32(len(bad)))

			if _, err := ParseFacialImageRecord(bad); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("ParseFacialImageRecord = %v, want ErrInvalidResponse", err)
			}
		})
	}
}
