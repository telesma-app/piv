package protocol

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestOCCMinutiaeWire(t *testing.T) {
	want := []OCCMinutia{{X: 0x12, Y: 0x34, Type: MinutiaRidgeEnding, Angle: 16}, {X: 0x56, Y: 0x78, Type: MinutiaBifurcation, Angle: 63}, {X: 0x9a, Y: 0xbc, Type: MinutiaOther, Angle: 0}}

	encoded := []byte{0x12, 0x34, 0x50, 0x56, 0x78, 0xbf, 0x9a, 0xbc, 0x00}
	if got := EncodeOCCMinutiae(want); !bytes.Equal(got, encoded) {
		t.Fatalf("OCC bytes = %x, want %x", got, encoded)
	}

	got, err := ParseOCCMinutiae(encoded)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("OCC minutiae = %+v, %v", got, err)
	}

	for _, bad := range [][]byte{{1}, {1, 2}, {1, 2, 0xc0}} {
		if _, err := ParseOCCMinutiae(bad); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("bad OCC %x: error = %v", bad, err)
		}
	}
}
