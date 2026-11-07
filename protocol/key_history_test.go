package protocol

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestEncodeKeyHistory(t *testing.T) {
	for _, test := range []struct {
		name    string
		history KeyHistory
		wire    string
	}{
		{
			name: "no retired keys", history: KeyHistory{},
			wire: "\xc1\x01\x00\xc2\x01\x00\xfe\x00",
		},
		{
			name: "on-card only", history: KeyHistory{KeysWithOnCardCerts: 20},
			wire: "\xc1\x01\x14\xc2\x01\x00\xfe\x00",
		},
		{
			name: "mixed and URL preserved",
			history: KeyHistory{
				KeysWithOnCardCerts: 17, KeysWithOffCardCerts: 3, OffCardCertURL: "http://EXAMPLE.test/%61",
			},
			wire: "\xc1\x01\x11\xc2\x01\x03\xf3\x17http://EXAMPLE.test/%61\xfe\x00",
		},
		{
			name:    "optional URL for on-card keys",
			history: KeyHistory{KeysWithOnCardCerts: 1, OffCardCertURL: "http://example.test/a"},
			wire:    "\xc1\x01\x01\xc2\x01\x00\xf3\x15http://example.test/a\xfe\x00",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := EncodeKeyHistory(test.history)
			if !bytes.Equal(got, []byte(test.wire)) {
				t.Errorf("EncodeKeyHistory = %x, want %x", got, test.wire)
			}
		})
	}
}

func TestParseKeyHistory(t *testing.T) {
	url := "http://example.test/" + strings.Repeat("a", 64)

	withURL := func(onCard, offCard byte) []byte {
		data := []byte{0xc1, 1, onCard, 0xc2, 1, offCard, 0xf3, byte(len(url))}
		data = append(data, url...)

		return append(data, 0xfe, 0)
	}
	for _, tc := range []struct {
		name string
		data []byte
		want KeyHistory
	}{
		{name: "no retired keys", data: []byte{0xc1, 1, 0, 0xc2, 1, 0, 0xfe, 0}},
		{name: "on-card only", data: []byte{0xc1, 1, 20, 0xc2, 1, 0}, want: KeyHistory{KeysWithOnCardCerts: 20}},
		{name: "off-card only", data: withURL(0, 20), want: KeyHistory{KeysWithOffCardCerts: 20, OffCardCertURL: url}},
		{name: "mixed", data: withURL(17, 3), want: KeyHistory{KeysWithOnCardCerts: 17, KeysWithOffCardCerts: 3, OffCardCertURL: url}},
		{name: "optional URL for on-card keys", data: withURL(1, 0), want: KeyHistory{KeysWithOnCardCerts: 1, OffCardCertURL: url}},
		{name: "reordered fields", data: []byte{0xc2, 1, 0, 0xc1, 1, 2}, want: KeyHistory{KeysWithOnCardCerts: 2}},
		{name: "unknown field", data: []byte{0xc1, 1, 1, 0xc2, 1, 0, 0x90, 2, 1, 2}, want: KeyHistory{KeysWithOnCardCerts: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseKeyHistory(tc.data)
			if err != nil {
				t.Fatal(err)
			}

			if got != tc.want {
				t.Errorf("key history = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestParseKeyHistoryRejectsInvalidData(t *testing.T) {
	withURL := func(value []byte) []byte {
		data := []byte{0xc1, 1, 1, 0xc2, 1, 0, 0xf3, byte(len(value))}
		return append(data, value...)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "empty"},
		{name: "missing on-card count", data: []byte{0xc2, 1, 0}},
		{name: "missing off-card count", data: []byte{0xc1, 1, 0}},
		{name: "empty on-card count", data: []byte{0xc1, 0, 0xc2, 1, 0}},
		{name: "long on-card count", data: []byte{0xc1, 2, 0, 1, 0xc2, 1, 0}},
		{name: "empty off-card count", data: []byte{0xc1, 1, 0, 0xc2, 0}},
		{name: "long off-card count", data: []byte{0xc1, 1, 0, 0xc2, 2, 0, 1}},
		{name: "on-card count out of range", data: []byte{0xc1, 1, 21, 0xc2, 1, 0}},
		{name: "off-card count out of range", data: []byte{0xc1, 1, 0, 0xc2, 1, 21}},
		{name: "total count out of range", data: []byte{0xc1, 1, 20, 0xc2, 1, 1}},
		{name: "duplicate on-card count", data: []byte{0xc1, 1, 0, 0xc2, 1, 0, 0xc1, 1, 1}},
		{name: "duplicate off-card count", data: []byte{0xc1, 1, 0, 0xc2, 1, 0, 0xc2, 1, 1}},
		{name: "duplicate URL", data: append(withURL([]byte("a")), 0xf3, 1, 'b')},
		{name: "empty URL", data: withURL(nil)},
		{name: "oversized URL", data: withURL([]byte(strings.Repeat("a", 119)))},
		{name: "non-ASCII URL", data: withURL([]byte("http://é.test/"))},
		{name: "control in URL", data: withURL([]byte{'a', 0, 'b'})},
		{name: "missing conditional URL", data: []byte{0xc1, 1, 0, 0xc2, 1, 1}},
		{name: "URL without retired keys", data: []byte{0xc1, 1, 0, 0xc2, 1, 0, 0xf3, 1, 'a'}},
		{name: "nonempty error detection code", data: []byte{0xc1, 1, 0, 0xc2, 1, 0, 0xfe, 1, 0}},
		{name: "duplicate error detection code", data: []byte{0xc1, 1, 0, 0xc2, 1, 0, 0xfe, 0, 0xfe, 0}},
		{name: "truncated TLV", data: []byte{0xc1, 1, 0, 0xc2, 1}},
		{name: "trailing invalid data", data: []byte{0xc1, 1, 0, 0xc2, 1, 0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseKeyHistory(tc.data); !errors.Is(err, ErrInvalidResponse) {
				t.Errorf("ParseKeyHistory error = %v, want ErrInvalidResponse", err)
			}
		})
	}
}
