package protocol

import (
	"bytes"
	"errors"
	"testing"

	"github.com/telesma-app/piv/internal/bertlv"
)

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
