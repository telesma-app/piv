package protocol

import (
	"bytes"
	"errors"
	"testing"
)

func TestParseObject(t *testing.T) {
	value, err := ParseObject([]byte{0x53, 1, 0x42}, 0x53)
	if err != nil || !bytes.Equal(value, []byte{0x42}) {
		t.Fatalf("ParseObject = (%x, %v)", value, err)
	}

	for _, raw := range [][]byte{{0x70, 0}, {0x53, 0, 0xfe, 0}, {0x53, 1}} {
		if _, err := ParseObject(raw, 0x53); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("ParseObject(%x) error = %v, want ErrInvalidResponse", raw, err)
		}
	}
}
