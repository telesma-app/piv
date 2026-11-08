package protocol

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestEncodePairingCode(t *testing.T) {
	want := []byte{0x99, 8, '0', '1', '2', '3', '4', '5', '6', '7', 0xfe, 0}

	got, err := EncodePairingCode("01234567")
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("EncodePairingCode = %x, want %x", got, want)
	}
}

func TestEncodePairingCodeRejectsInvalidCode(t *testing.T) {
	for _, code := range []string{"", "1234567", "123456789", "1234567a", "1234 678", "１２３４５６７８", "123456\x00\xff"} {
		if got, err := EncodePairingCode(code); err == nil || got != nil {
			t.Errorf("EncodePairingCode(%q) = %x, %v", code, got, err)
		} else if code != "" && strings.Contains(err.Error(), code) {
			t.Errorf("error discloses pairing code: %v", err)
		}
	}
}

func TestParsePairingCode(t *testing.T) {
	for _, data := range [][]byte{
		{0x99, 8, '0', '1', '2', '3', '4', '5', '6', '7'},
		{0x99, 8, '0', '1', '2', '3', '4', '5', '6', '7', 0xfe, 0},
		{0x90, 1, 0xff, 0xfe, 0, 0x99, 8, '0', '1', '2', '3', '4', '5', '6', '7', 0x90, 0},
	} {
		got, err := ParsePairingCode(data)
		if err != nil || got != "01234567" {
			t.Errorf("ParsePairingCode(%x) = %q, %v", data, got, err)
		}
	}
}

func TestParsePairingCodeRejectsInvalidData(t *testing.T) {
	valid := []byte{0x99, 8, '0', '1', '2', '3', '4', '5', '6', '7'}
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "missing code"},
		{name: "only EDC", data: []byte{0xfe, 0}},
		{name: "empty code", data: []byte{0x99, 0}},
		{name: "short code", data: []byte{0x99, 7, '0', '1', '2', '3', '4', '5', '6'}},
		{name: "long code", data: []byte{0x99, 9, '0', '1', '2', '3', '4', '5', '6', '7', '8'}},
		{name: "letter", data: []byte{0x99, 8, 'a', '1', '2', '3', '4', '5', '6', '7'}},
		{name: "non-ASCII", data: []byte{0x99, 8, 0x80, '1', '2', '3', '4', '5', '6', '7'}},
		{name: "duplicate code", data: bytes.Repeat(valid, 2)},
		{name: "nonempty EDC", data: append(bytes.Clone(valid), 0xfe, 1, 0)},
		{name: "duplicate EDC", data: append(bytes.Clone(valid), 0xfe, 0, 0xfe, 0)},
		{name: "truncated TLV", data: valid[:len(valid)-1]},
		{name: "trailing byte", data: append(bytes.Clone(valid), 0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got, err := ParsePairingCode(test.data); !errors.Is(err, ErrInvalidResponse) || got != "" {
				t.Errorf("ParsePairingCode = %q, %v, want ErrInvalidResponse", got, err)
			}
		})
	}
}
