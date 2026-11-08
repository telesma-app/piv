package protocol

import (
	"bytes"
	"errors"
	"testing"

	"github.com/telesma-app/bertlv"
)

func TestParseCertificateData(t *testing.T) {
	der := []byte{0x30, 0}
	for _, test := range []struct {
		name   string
		value  []byte
		info   byte
		mscuid []byte
	}{
		{name: "absent MSCUID", value: der},
		{name: "empty MSCUID", value: der, mscuid: []byte{}},
		{name: "legacy MSCUID", value: der, mscuid: []byte("legacy-identifier")},
		{name: "GZIP", value: certificateGZIP(t, der), info: 1, mscuid: []byte("legacy-identifier")},
		{name: "maximum MSCUID", value: der, mscuid: bytes.Repeat([]byte{'A'}, 38)},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := certificateObject(test.value, test.info)
			if test.mscuid != nil {
				data = bertlv.Append(data, 0x72, test.mscuid)
			}

			got, err := ParseCertificateData(data)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(got.DER, der) || !bytes.Equal(got.MSCUID, test.mscuid) || (got.MSCUID == nil) != (test.mscuid == nil) {
				t.Errorf("certificate = %+v, want DER %x, MSCUID %x", got, der, test.mscuid)
			}

			encoded := EncodeCertificateData(got)

			want := []byte{0x70, 2, 0x30, 0, 0x71, 1, 0}
			if test.mscuid != nil {
				want = append(want, 0x72, byte(len(test.mscuid)))
				want = append(want, test.mscuid...)
			}

			want = append(want, 0xfe, 0)

			if !bytes.Equal(encoded, want) {
				t.Errorf("encoded certificate = %x, want %x", encoded, want)
			}
		})
	}
}

func TestParseCertificateDataBorrowsMSCUID(t *testing.T) {
	data := []byte{0x70, 2, 0x30, 0, 0x71, 1, 0, 0x72, 1, 'A', 0xfe, 0}

	got, err := ParseCertificateData(data)
	if err != nil {
		t.Fatal(err)
	}

	data[9] = 'B'

	if got.MSCUID[0] != 'B' || cap(got.MSCUID) != len(got.MSCUID) {
		t.Errorf("MSCUID = %q (capacity %d), want borrowed B with capacity 1", got.MSCUID, cap(got.MSCUID))
	}
}

func TestParseCertificateDataRejectsInvalidMSCUID(t *testing.T) {
	for _, test := range []struct {
		name   string
		fields []byte
	}{
		{name: "duplicate", fields: []byte{0x72, 0, 0x72, 0}},
		{name: "too long", fields: append([]byte{0x72, 39}, make([]byte, 39)...)},
		{name: "truncated", fields: []byte{0x72, 2, 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := append([]byte{0x70, 2, 0x30, 0, 0x71, 1, 0}, test.fields...)

			if _, err := ParseCertificateData(data); !errors.Is(err, ErrInvalidResponse) {
				t.Errorf("ParseCertificateData = %v, want ErrInvalidResponse", err)
			}
		})
	}
}
