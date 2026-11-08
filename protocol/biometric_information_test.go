package protocol

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestBiometricInformationWire(t *testing.T) {
	// PIV BIT layout from SP 800-76-2 Table 7, with two different fingers
	// and comparison limits. Outer 7F61 is removed by GetData.
	encoded := biometricHex(t, "020102"+
		"7f601c830196a1178101088201098702010188020005b10781020a28820100"+
		"7f601c830197a11781010882010a8702010188020005b10781020c30820101")
	want := []BiometricInformationTemplate{
		{Reference: PrimaryFingerOCC, Finger: BiometricRightIndex, FormatOwner: 0x0101, FormatType: 0x0005, MinutiaeMinimum: 10, MinutiaeMaximum: 40},
		{Reference: SecondaryFingerOCC, Finger: BiometricLeftIndex, FormatOwner: 0x0101, FormatType: 0x0005, MinutiaeMinimum: 12, MinutiaeMaximum: 48, MinutiaeOrder: 1},
	}

	parsed, err := ParseBiometricInformation(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(EncodeBiometricInformation(BiometricInformation{Templates: want}), encoded) {
		t.Fatal("BIT encoded bytes differ from independent layout")
	}

	for i := range want {
		got := parsed.Templates[i]

		got.Raw = nil
		if !reflect.DeepEqual(got, want[i]) {
			t.Errorf("BIT %d = %+v, want %+v", i, got, want[i])
		}
	}

	if &parsed.Raw[0] != &encoded[0] || &parsed.Templates[0].Raw[0] != &encoded[6] {
		t.Error("BIT bytes do not borrow input")
	}

	zero, err := ParseBiometricInformation([]byte{2, 1, 0})
	if err != nil || len(zero.Templates) != 0 || !bytes.Equal(EncodeBiometricInformation(zero), []byte{2, 1, 0}) {
		t.Fatalf("empty BIT = %+v, %v", zero, err)
	}
}

func TestBiometricInformationRejectsMalformedExternalObjects(t *testing.T) {
	valid := biometricHex(t, "0201017f601c830196a1178101088201098702010188020005b10781020a28820100")
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "count mismatch", mutate: func(b []byte) []byte { b[2] = 2; return b }},
		{name: "reference order", mutate: func(b []byte) []byte { b[8] = 0x97; return b }},
		{name: "parameters outside header", mutate: func(b []byte) []byte { b[10] = 0x0e; return b }},
		{name: "wrong modality", mutate: func(b []byte) []byte { b[13] = 0x02; return b }},
		{name: "wrong owner", mutate: func(b []byte) []byte { b[20] = 0x02; return b }},
		{name: "wrong format", mutate: func(b []byte) []byte { b[24] = 0x06; return b }},
		{name: "inverted limits", mutate: func(b []byte) []byte { b[29] = 0xff; return b }},
		{name: "feature handling", mutate: func(b []byte) []byte { b[len(b)-3] = 0x83; return b }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseBiometricInformation(tc.mutate(bytes.Clone(valid)))
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("error = %v", err)
			}
		})
	}

	for end := range len(valid) {
		if _, err := ParseBiometricInformation(valid[:end]); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("prefix %d: error = %v", end, err)
		}
	}
}
