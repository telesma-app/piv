package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/telesma-app/bertlv"
)

func TestEncodeCCC(t *testing.T) {
	containerVersion, grammarVersion, pkcs15 := byte(0x21), byte(0x22), byte(0)
	ccc := CCC{
		CardIdentifier: &[21]byte{1, 2}, CapabilityContainerVersion: &containerVersion,
		CapabilityGrammarVersion: &grammarVersion, ApplicationsCardURL: []byte{0xa0, 1},
		PKCS15: &pkcs15, DataModel: 0x10, AccessControlRuleTable: make([]byte, 17),
	}
	want := []byte{
		0xf0, 21, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0xf1, 1, 0x21, 0xf2, 1, 0x22, 0xf3, 2, 0xa0, 1, 0xf4, 1, 0, 0xf5, 1, 0x10,
		0xf6, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0xf7, 0, 0xfa, 0, 0xfb, 0, 0xfc, 0, 0xfd, 0, 0xfe, 0,
	}

	got := EncodeCCC(ccc)
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeCCC = %x, want %x", got, want)
	}

	parsed, err := ParseCCC(got)
	if err != nil {
		t.Fatal(err)
	}

	parsed.Raw = nil
	if !reflect.DeepEqual(parsed, ccc) {
		t.Errorf("CCC = %+v, want %+v", parsed, ccc)
	}
}

func TestEncodeCCCEmptyMandatoryFields(t *testing.T) {
	want := []byte{
		0xf0, 0, 0xf1, 0, 0xf2, 0, 0xf3, 0, 0xf4, 0, 0xf5, 1, 0x10,
		0xf6, 0, 0xf7, 0, 0xfa, 0, 0xfb, 0, 0xfc, 0, 0xfd, 0, 0xfe, 0,
	}

	got := EncodeCCC(CCC{DataModel: 0x10})
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeCCC = %x, want %x", got, want)
	}

	if _, err := ParseCCC(got); err != nil {
		t.Fatal(err)
	}
}

func TestParseCCCMinimalPIVObjects(t *testing.T) {
	for _, data := range [][]byte{
		{0xf5, 1, 0x10},
		{
			0xf0, 0, 0xf1, 0, 0xf2, 0, 0xf3, 0, 0xf4, 0, 0xf5, 1, 0x10,
			0xf6, 0, 0xf7, 0, 0xfa, 0, 0xfb, 0, 0xfc, 0, 0xfd, 0, 0xfe, 0,
		},
	} {
		got, err := ParseCCC(data)
		if err != nil {
			t.Fatal(err)
		}

		if got.DataModel != 0x10 || got.CardIdentifier != nil || got.CapabilityContainerVersion != nil || got.CapabilityGrammarVersion != nil || got.PKCS15 != nil {
			t.Fatalf("CCC = %+v", got)
		}

		if &got.Raw[0] != &data[0] || !bytes.Equal(got.Raw, data) {
			t.Fatal("Raw did not preserve and borrow the complete object")
		}
	}
}

func TestParseCCCPopulatedFieldsAndOwnership(t *testing.T) {
	data := bertlv.Append(nil, 0xf0, bytes.Repeat([]byte{0x42}, 21))
	data = append(data, 0xf1, 1, 0x21, 0xf2, 1, 0x22, 0xf4, 1, 0, 0xf5, 1, 0x10)
	urlOffset := len(data) + 2
	data = bertlv.Append(data, 0xf3, []byte{0, 0xff, 0x30, 0x80})
	tableOffset := len(data) + 2
	data = bertlv.Append(data, 0xf6, bytes.Repeat([]byte{0x99}, 17))

	got, err := ParseCCC(data)
	if err != nil {
		t.Fatal(err)
	}

	if got.CardIdentifier != (*[21]byte)(data[2:23]) || got.CapabilityContainerVersion != &data[25] || got.CapabilityGrammarVersion != &data[28] || got.PKCS15 != &data[31] {
		t.Fatal("CCC scalar fields do not borrow the object")
	}

	if *got.CapabilityContainerVersion != 0x21 || *got.CapabilityGrammarVersion != 0x22 || *got.PKCS15 != 0 || got.DataModel != 0x10 {
		t.Fatalf("CCC scalar fields = %+v", got)
	}

	if &got.ApplicationsCardURL[0] != &data[urlOffset] || &got.AccessControlRuleTable[0] != &data[tableOffset] {
		t.Fatal("CCC opaque fields do not borrow the object")
	}

	data[2] = 0x70
	data[25] = 0x71
	data[urlOffset] = 0x72
	data[tableOffset] = 0x73

	if got.CardIdentifier[0] != 0x70 || *got.CapabilityContainerVersion != 0x71 || got.ApplicationsCardURL[0] != 0x72 || got.AccessControlRuleTable[0] != 0x73 {
		t.Fatal("CCC views did not retain their borrowed ownership")
	}
}

func TestParseCCCPreservesUnknownValuesAndLegacyFields(t *testing.T) {
	data := []byte{
		0xe3, 2, 0x11, 0x22, // Removed Extended Application CardURL.
		0xb4, 1, 0x33, // Removed Security Object Buffer.
		0xf8, 0, 0xf9, 0, // Unassigned holes in the F0 through FE range.
		0x90, 1, 0x44, 0x90, 1, 0x55,
		0xf4, 1, 0xff, 0xf5, 0x81, 1, 0x99,
	}

	got, err := ParseCCC(data)
	if err != nil {
		t.Fatal(err)
	}

	if got.DataModel != 0x99 || got.PKCS15 == nil || *got.PKCS15 != 0xff || !bytes.Equal(got.Raw, data) {
		t.Fatalf("CCC unknown values = %+v", got)
	}
}

func TestParseCCCPreservesEmptyAndAbsentFields(t *testing.T) {
	absent, err := ParseCCC([]byte{0xf5, 1, 0x10})
	if err != nil {
		t.Fatal(err)
	}

	empty, err := ParseCCC([]byte{0xf5, 1, 0x10, 0xf3, 0, 0xf6, 0, 0xf4, 0})
	if err != nil {
		t.Fatal(err)
	}

	if absent.ApplicationsCardURL != nil || absent.AccessControlRuleTable != nil || empty.ApplicationsCardURL == nil || empty.AccessControlRuleTable == nil || empty.PKCS15 != nil {
		t.Fatalf("absent/empty CCC = %+v / %+v", absent, empty)
	}

	if bytes.Equal(absent.Raw, empty.Raw) {
		t.Fatal("Raw lost the presence of empty fields")
	}
}

func TestParseCCCRejectsMalformedData(t *testing.T) {
	base := []byte{0xf5, 1, 0x10}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "empty"},
		{name: "missing data model", data: []byte{0xf0, 0}},
		{name: "empty data model", data: []byte{0xf5, 0}},
		{name: "long data model", data: []byte{0xf5, 2, 0, 0x10}},
		{name: "duplicate data model", data: slices.Concat(base, base)},
		{name: "truncated TLV", data: slices.Concat(base, []byte{0xf3, 2, 1})},
		{name: "indefinite length", data: slices.Concat(base, []byte{0x90, 0x80, 0, 0})},
		{name: "trailing invalid data", data: slices.Concat(base, []byte{0})},
		{name: "unexpected outer template", data: bertlv.Append(nil, 0x53, base)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseCCC(tc.data); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("ParseCCC = %v, want ErrInvalidResponse", err)
			}
		})
	}

	for _, field := range []struct {
		tag     uint32
		lengths []int
	}{
		{tag: 0xf0, lengths: []int{1, 20, 22}},
		{tag: 0xf1, lengths: []int{2}},
		{tag: 0xf2, lengths: []int{2}},
		{tag: 0xf3, lengths: []int{129}},
		{tag: 0xf4, lengths: []int{2}},
		{tag: 0xf6, lengths: []int{1, 16, 18}},
		{tag: 0xf7, lengths: []int{1}},
		{tag: 0xfa, lengths: []int{1}},
		{tag: 0xfb, lengths: []int{1}},
		{tag: 0xfc, lengths: []int{1}},
		{tag: 0xfd, lengths: []int{1}},
		{tag: 0xfe, lengths: []int{1}},
	} {
		for _, length := range field.lengths {
			t.Run(fmt.Sprintf("tag %x length %d", field.tag, length), func(t *testing.T) {
				data := bertlv.Append(slices.Clone(base), field.tag, make([]byte, length))
				if _, err := ParseCCC(data); !errors.Is(err, ErrInvalidResponse) {
					t.Fatalf("ParseCCC = %v, want ErrInvalidResponse", err)
				}
			})
		}
	}

	for _, tag := range []uint32{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf6, 0xf7, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe} {
		t.Run(fmt.Sprintf("duplicate empty tag %x", tag), func(t *testing.T) {
			data := bertlv.Append(slices.Clone(base), tag, nil)

			data = bertlv.Append(data, tag, nil)
			if _, err := ParseCCC(data); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("ParseCCC = %v, want ErrInvalidResponse", err)
			}
		})
	}
}

func TestParseCCCAcceptsMaximumApplicationsCardURL(t *testing.T) {
	data := bertlv.Append([]byte{0xf5, 1, 0x10}, 0xf3, make([]byte, 128))

	got, err := ParseCCC(data)
	if err != nil || len(got.ApplicationsCardURL) != 128 {
		t.Fatalf("CCC ApplicationsCardURL = %+v, %v", got, err)
	}
}
