package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/telesma-app/bertlv"
)

func TestEncodeCHUID(t *testing.T) {
	chuid := CHUID{
		FASCN: [25]byte{1, 2}, GUID: [16]byte{3, 4},
		ExpirationDate: time.Date(2030, time.February, 28, 0, 0, 0, 0, time.UTC),
		CardholderUUID: &[16]byte{5, 6}, IssuerSignature: []byte{0x30, 0},
	}
	want := []byte{
		0x30, 25, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0x34, 16, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0x35, 8, '2', '0', '3', '0', '0', '2', '2', '8',
		0x36, 16, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0x3e, 2, 0x30, 0, 0xfe, 0,
	}

	got := EncodeCHUID(chuid)
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeCHUID = %x, want %x", got, want)
	}

	parsed, err := ParseCHUID(got)
	if err != nil {
		t.Fatal(err)
	}

	parsed.Raw = nil
	if !reflect.DeepEqual(parsed, chuid) {
		t.Errorf("CHUID = %+v, want %+v", parsed, chuid)
	}
}

func TestEncodeCHUIDOptionalFields(t *testing.T) {
	chuid := CHUID{ExpirationDate: time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)}
	for _, signature := range [][]byte{nil, {}} {
		chuid.IssuerSignature = signature

		data := EncodeCHUID(chuid)

		got, err := ParseCHUID(data)
		if err != nil {
			t.Fatal(err)
		}

		if got.CardholderUUID != nil || (got.IssuerSignature == nil) != (signature == nil) {
			t.Errorf("optional fields = %+v, signature input %v", got, signature)
		}

		wantSuffix := []byte{0xfe, 0}
		if signature != nil {
			wantSuffix = []byte{0x3e, 0, 0xfe, 0}
		}

		if !bytes.HasSuffix(data, wantSuffix) {
			t.Errorf("CHUID suffix = %x, want %x", data, wantSuffix)
		}
	}
}

func chuidFields() (fascn, guid, expiration []byte) {
	fascn = append([]byte{0x30, 25}, bytes.Repeat([]byte{0x42}, 25)...)
	guid = append([]byte{0x34, 16}, bytes.Repeat([]byte{0xa5}, 16)...)
	expiration = append([]byte{0x35, 8}, "20300101"...)

	return fascn, guid, expiration
}

func TestParseCHUIDUnsignedTokenLayout(t *testing.T) {
	fascn, guid, expiration := chuidFields()
	// PIV tokens commonly use this 59-byte layout with an empty issuer
	// signature, instead of a personalized government-issued CHUID signature.
	data := slices.Concat(fascn, guid, expiration, []byte{0x3e, 0, 0xfe, 0})

	got, err := ParseCHUID(data)
	if err != nil {
		t.Fatal(err)
	}

	if got.FASCN != [25]byte(fascn[2:]) || got.GUID != [16]byte(guid[2:]) {
		t.Fatalf("CHUID identifiers = %x, %x", got.FASCN, got.GUID)
	}

	if want := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC); got.ExpirationDate != want {
		t.Fatalf("expiration date = %v, want %v", got.ExpirationDate, want)
	}

	if got.CardholderUUID != nil || got.IssuerSignature == nil || len(got.IssuerSignature) != 0 {
		t.Fatalf("optional fields = UUID %v, signature %#v", got.CardholderUUID, got.IssuerSignature)
	}

	if len(data) != 59 || !bytes.Equal(got.Raw, data) || &got.Raw[0] != &data[0] {
		t.Fatal("Raw did not preserve and borrow the complete token object")
	}

	got, err = ParseCHUID(slices.Concat(fascn, guid, expiration))
	if err != nil || got.IssuerSignature != nil {
		t.Fatalf("CHUID without a signature field = %+v, %v", got, err)
	}
}

func TestParseCHUIDPreservesOriginalEncodingAndBorrowedFields(t *testing.T) {
	fascn, _, _ := chuidFields()
	guid := bytes.Repeat([]byte{0x11}, 16)
	// A non-minimal BER length is retained; parsing must not rebuild the
	// original representation of content that might be signed.
	data := append([]byte{0x34, 0x81, 16}, guid...)
	data = append(data, fascn...)
	data = bertlv.Append(data, 0x35, []byte("20240229"))
	uuidOffset := len(data) + 2
	data = bertlv.Append(data, 0x36, bytes.Repeat([]byte{0x22}, 16))
	data = bertlv.Append(data, 0x3d, []byte{1}) // Removed Authentication Key Map.
	data = bertlv.Append(data, 0x90, []byte{2})
	data = bertlv.Append(data, 0x90, []byte{3})
	signatureOffset := len(data) + 2
	data = bertlv.Append(data, 0x3e, []byte{0x30, 0x03, 0x02, 0x01, 0})
	original := bytes.Clone(data)

	got, err := ParseCHUID(data)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got.Raw, original) || got.Raw[1] != 0x81 || !bytes.Equal(got.IssuerSignature, data[signatureOffset:]) {
		t.Fatal("CHUID changed the original object or interpreted its opaque signature")
	}

	if got.CardholderUUID != (*[16]byte)(data[uuidOffset:uuidOffset+16]) || &got.IssuerSignature[0] != &data[signatureOffset] {
		t.Fatal("CHUID UUID or signature does not borrow the object")
	}

	data[uuidOffset] = 0x77
	data[signatureOffset] = 0x78
	data[3] = 0x79

	if got.CardholderUUID[0] != 0x77 || got.IssuerSignature[0] != 0x78 || got.GUID[0] != 0x11 {
		t.Fatal("CHUID did not preserve the documented borrowed views and value identifiers")
	}
}

func TestParseCHUIDRejectsInvalidFields(t *testing.T) {
	fascn, guid, expiration := chuidFields()
	base := slices.Concat(fascn, guid, expiration)

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "empty"},
		{name: "missing FASC-N", data: slices.Concat(guid, expiration)},
		{name: "missing GUID", data: slices.Concat(fascn, expiration)},
		{name: "missing expiration date", data: slices.Concat(fascn, guid)},
		{name: "duplicate FASC-N", data: slices.Concat(base, fascn)},
		{name: "duplicate GUID", data: slices.Concat(base, guid)},
		{name: "duplicate expiration date", data: slices.Concat(base, expiration)},
		{name: "duplicate UUID", data: slices.Concat(base, bertlv.Append(nil, 0x36, make([]byte, 16)), bertlv.Append(nil, 0x36, make([]byte, 16)))},
		{name: "duplicate signature", data: slices.Concat(base, []byte{0x3e, 0, 0x3e, 0})},
		{name: "nonempty error detection code", data: slices.Concat(base, []byte{0xfe, 1, 0})},
		{name: "duplicate error detection code", data: slices.Concat(base, []byte{0xfe, 0, 0xfe, 0})},
		{name: "truncated field", data: slices.Concat(base, []byte{0x90, 2, 1})},
		{name: "indefinite length", data: slices.Concat(base, []byte{0x90, 0x80, 0, 0})},
		{name: "trailing octet", data: slices.Concat(base, []byte{0})},
		{name: "unexpected outer template", data: bertlv.Append(nil, 0x53, base)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseCHUID(tc.data); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("ParseCHUID = %v, want ErrInvalidResponse", err)
			}
		})
	}

	for _, field := range []struct {
		tag   uint32
		width int
		other []byte
	}{
		{tag: 0x30, width: 25, other: slices.Concat(guid, expiration)},
		{tag: 0x34, width: 16, other: slices.Concat(fascn, expiration)},
		{tag: 0x35, width: 8, other: slices.Concat(fascn, guid)},
		{tag: 0x36, width: 16, other: base},
	} {
		for _, length := range []int{0, field.width - 1, field.width + 1} {
			t.Run(fmt.Sprintf("tag %x length %d", field.tag, length), func(t *testing.T) {
				data := bertlv.Append(slices.Clone(field.other), field.tag, make([]byte, length))
				if _, err := ParseCHUID(data); !errors.Is(err, ErrInvalidResponse) {
					t.Fatalf("ParseCHUID = %v, want ErrInvalidResponse", err)
				}
			})
		}
	}
}

func TestParseCHUIDExpirationDate(t *testing.T) {
	fascn, guid, _ := chuidFields()
	for _, date := range []string{"20260229", "20241301", "20240100", "20240132", "2024 101", "2024\x0011", "20a40101"} {
		data := bertlv.Append(slices.Concat(fascn, guid), 0x35, []byte(date))
		if _, err := ParseCHUID(data); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("expiration %q accepted: %v", date, err)
		}
	}

	data := bertlv.Append(slices.Concat(fascn, guid), 0x35, []byte("20000101"))

	got, err := ParseCHUID(data)
	if err != nil || got.ExpirationDate.Year() != 2000 {
		t.Fatalf("expired CHUID metadata = %+v, %v", got, err)
	}
}
