package protocol

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/telesma-app/bertlv"
)

func TestParseOffCardCertURL(t *testing.T) {
	const encoded = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

	want := [32]byte{
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
	}

	for _, value := range []string{
		"http://example.test/" + encoded,
		"HTTP://EXAMPLE.test/" + strings.ToUpper(encoded),
		"http://example.test./" + encoded,
		"http://1-example.test/" + encoded,
		"http://" + strings.Repeat("a", 41) + ".test/" + encoded,
	} {
		t.Run(value, func(t *testing.T) {
			got, err := ParseOffCardCertURL(value)
			if err != nil {
				t.Fatal(err)
			}

			if got != want {
				t.Errorf("digest = %x, want %x", got, want)
			}
		})
	}
}

func TestParseOffCardCertURLRejectsInvalidData(t *testing.T) {
	const (
		digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
		valid  = "http://example.test/" + digest
	)

	for _, test := range []struct {
		name  string
		value string
	}{
		{name: "empty"},
		{name: "HTTPS", value: "https://example.test/" + digest},
		{name: "relative URL", value: "example.test/" + digest},
		{name: "missing digest", value: "http://example.test"},
		{name: "missing host", value: "http:///" + digest},
		{name: "IPv4 address", value: "http://192.0.2.1/" + digest},
		{name: "IPv6 address", value: "http://[2001:db8::1]/" + digest},
		{name: "port", value: "http://example.test:80/" + digest},
		{name: "user information", value: "http://user@example.test/" + digest},
		{name: "empty DNS label", value: "http://example..test/" + digest},
		{name: "leading DNS hyphen", value: "http://-example.test/" + digest},
		{name: "trailing DNS hyphen", value: "http://example-.test/" + digest},
		{name: "invalid DNS character", value: "http://example_test/" + digest},
		{name: "non-ASCII DNS name", value: "http://é.test/" + digest},
		{name: "oversized URL", value: "http://" + strings.Repeat("a", 42) + ".test/" + digest},
		{name: "short digest", value: valid[:len(valid)-1]},
		{name: "nonhex digest", value: "http://example.test/g" + digest[1:]},
		{name: "escaped digest", value: "http://example.test/%62" + digest[1:]},
		{name: "additional path", value: "http://example.test/certs/" + digest},
		{name: "query", value: valid + "?"},
		{name: "fragment", value: valid + "#"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got, err := ParseOffCardCertURL(test.value); !errors.Is(err, ErrInvalidResponse) || got != [32]byte{} {
				t.Errorf("ParseOffCardCertURL = %x, %v, want ErrInvalidResponse", got, err)
			}
		})
	}
}

func TestParseOffCardKeyHistoryFile(t *testing.T) {
	// SEQUENCE OF { OCTET STRING keyReference, Certificate SEQUENCE }.
	// These framed certificates intentionally do not require X.509 parsing.
	data := []byte{
		0x30, 17,
		0x30, 8, 4, 1, 0x95, 0x30, 3, 2, 1, 1,
		0x30, 5, 4, 1, 0x82, 0x30, 0,
	}

	got, err := ParseOffCardKeyHistoryFile(data)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 2 || got[0].Key != RetiredKey20 || got[1].Key != RetiredKey1 {
		t.Fatalf("certificates = %+v", got)
	}

	if !bytes.Equal(got[0].DER, []byte{0x30, 3, 2, 1, 1}) || !bytes.Equal(got[1].DER, []byte{0x30, 0}) {
		t.Errorf("certificate DER = %x / %x", got[0].DER, got[1].DER)
	}

	data[11] = 2

	if got[0].DER[4] != 2 {
		t.Error("certificate DER does not borrow the file")
	}
}

func TestParseOffCardKeyHistoryFileCertificate(t *testing.T) {
	der := certificateDER(t)
	data := offCardFile(offCardEntry([]byte{0x82}, der))

	got, err := ParseOffCardKeyHistoryFile(data)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 1 || got[0].Key != RetiredKey1 || !bytes.Equal(got[0].DER, der) {
		t.Errorf("certificate = %+v", got)
	}
}

func TestParseOffCardKeyHistoryFileAllRetiredKeys(t *testing.T) {
	var entries [][]byte

	for key := RetiredKey1; key <= RetiredKey20; key++ {
		entries = append(entries, offCardEntry([]byte{byte(key)}, []byte{0x30, 0}))
	}

	got, err := ParseOffCardKeyHistoryFile(offCardFile(entries...))
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 20 || got[19].Key != RetiredKey20 {
		t.Errorf("certificates = %+v", got)
	}
}

func TestParseOffCardKeyHistoryFileRejectsInvalidData(t *testing.T) {
	entry := offCardEntry([]byte{0x82}, []byte{0x30, 0})
	valid := offCardFile(entry)

	var tooMany [][]byte

	for key := byte(0x82); key <= 0x96; key++ {
		tooMany = append(tooMany, offCardEntry([]byte{key}, []byte{0x30, 0}))
	}

	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "empty"},
		{name: "empty file", data: []byte{0x30, 0}},
		{name: "wrong outer tag", data: []byte{5, 0}},
		{name: "primitive outer SEQUENCE", data: []byte{0x10, 0}},
		{name: "wrong outer class", data: []byte{0x70, 0}},
		{name: "trailing file data", data: append(bytes.Clone(valid), 5, 0)},
		{name: "truncated file", data: valid[:len(valid)-1]},
		{name: "nonminimal file length", data: append([]byte{0x30, 0x81, 7}, entry...)},
		{name: "indefinite file length", data: append(append([]byte{0x30, 0x80}, entry...), 0, 0)},
		{name: "wrong entry tag", data: offCardFile([]byte{5, 0})},
		{name: "primitive entry SEQUENCE", data: offCardFile([]byte{0x10, 5, 4, 1, 0x82, 0x30, 0})},
		{name: "empty entry", data: offCardFile([]byte{0x30, 0})},
		{name: "missing reference", data: offCardFile([]byte{0x30, 2, 0x30, 0})},
		{name: "wrong reference tag", data: offCardFile([]byte{0x30, 5, 2, 1, 0x82, 0x30, 0})},
		{name: "constructed reference", data: offCardFile([]byte{0x30, 5, 0x24, 1, 0x82, 0x30, 0})},
		{name: "empty reference", data: offCardFile(offCardEntry(nil, []byte{0x30, 0}))},
		{name: "long reference", data: offCardFile(offCardEntry([]byte{0x82, 0x83}, []byte{0x30, 0}))},
		{name: "primary key", data: offCardFile(offCardEntry([]byte{0x9d}, []byte{0x30, 0}))},
		{name: "reference below retired range", data: offCardFile(offCardEntry([]byte{0x81}, []byte{0x30, 0}))},
		{name: "reference above retired range", data: offCardFile(offCardEntry([]byte{0x96}, []byte{0x30, 0}))},
		{name: "duplicate reference", data: offCardFile(entry, entry)},
		{name: "missing certificate", data: offCardFile(offCardEntry([]byte{0x82}, nil))},
		{name: "wrong certificate tag", data: offCardFile(offCardEntry([]byte{0x82}, []byte{5, 0}))},
		{name: "primitive certificate SEQUENCE", data: offCardFile(offCardEntry([]byte{0x82}, []byte{0x10, 0}))},
		{name: "tagged certificate", data: offCardFile(offCardEntry([]byte{0x82}, []byte{0xb0, 0}))},
		{name: "nonminimal certificate length", data: offCardFile(offCardEntry([]byte{0x82}, []byte{0x30, 0x81, 0}))},
		{name: "truncated certificate", data: offCardFile(offCardEntry([]byte{0x82}, []byte{0x30, 3, 2, 1}))},
		{name: "extra entry member", data: offCardFile(offCardEntry([]byte{0x82}, []byte{0x30, 0, 5, 0}))},
		{name: "trailing entry data", data: offCardFile(entry, []byte{0})},
		{name: "too many entries", data: offCardFile(tooMany...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got, err := ParseOffCardKeyHistoryFile(test.data); !errors.Is(err, ErrInvalidResponse) || got != nil {
				t.Errorf("ParseOffCardKeyHistoryFile = %+v, %v, want ErrInvalidResponse", got, err)
			}
		})
	}
}

func offCardEntry(reference, certificate []byte) []byte {
	data := bertlv.Append(nil, 4, reference)
	return bertlv.Append(nil, 0x30, append(data, certificate...))
}

func offCardFile(entries ...[]byte) []byte {
	return bertlv.Append(nil, 0x30, bytes.Join(entries, nil))
}
