package protocol

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/telesma-app/piv/internal/bertlv"
)

func TestParseApplicationPropertyTemplate(t *testing.T) {
	// SELECT metadata can split the PIV identifier into the PIX in 4F and the
	// NIST RID in 79/4F. Keep both wire values instead of manufacturing an AID.
	data := []byte{
		0x61, 0x11,
		0x4f, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
		0x79, 0x07, 0x4f, 0x05, 0xa0, 0x00, 0x00, 0x03, 0x08,
	}

	got, err := ParseApplicationPropertyTemplate(data)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got.AID, []byte{0, 0, 0x10, 0, 1, 0}) {
		t.Errorf("AID = %x", got.AID)
	}

	if !bytes.Equal(got.TagAllocationAuthorityAID, []byte{0xa0, 0, 0, 3, 8}) {
		t.Errorf("tag allocation authority AID = %x", got.TagAllocationAuthorityAID)
	}

	if got.Algorithms != nil || got.ApplicationLabel != "" || got.ApplicationURL != "" {
		t.Errorf("unexpected optional metadata: %+v", got)
	}

	data[4] = 0x42

	if got.AID[0] != 0x42 {
		t.Error("parsed AID does not borrow the response")
	}
}

func TestParseApplicationMetadata(t *testing.T) {
	data := []byte{
		0x4f, 0x0b, 0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
		0x79, 0x07, 0x4f, 0x05, 0xa0, 0x00, 0x00, 0x03, 0x08,
		0x50, 0x03, 'P', 'I', 'V',
		0x5f, 0x50, 0x08, 'h', 't', 't', 'p', ':', '/', '/', 'x',
		0xac, 0x0c,
		0x80, 0x01, 0x27, 0x80, 0x01, 0xf0, 0x80, 0x01, 0xf0, 0x06, 0x01, 0x00,
		0x90, 0x01, 0xff,
	}

	got, err := ParseApplicationPropertyTemplate(bertlv.Append(nil, 0x61, data))
	if err != nil {
		t.Fatal(err)
	}

	if got.ApplicationLabel != "PIV" || got.ApplicationURL != "http://x" {
		t.Errorf("application metadata = %+v", got)
	}

	if !slices.Equal(got.Algorithms, []Algorithm{0x27, 0xf0, 0xf0}) {
		t.Errorf("algorithms = %x, want 27 f0 f0", got.Algorithms)
	}

	if !bytes.Equal(got.TagAllocationAuthorityAID, []byte{0xa0, 0, 0, 3, 8}) {
		t.Errorf("tag allocation authority AID = %x", got.TagAllocationAuthorityAID)
	}
}

func TestParseApplicationRepeatedAlgorithmTemplates(t *testing.T) {
	// PivApplet v0.9.0 SELECT trace, from the implementation's issue #51:
	// https://github.com/arekinath/PivApplet/issues/51
	// The applet emits a separate AC/80/06 template for each algorithm.
	data := []byte{
		0x61, 0x81, 0x66,
		0x4f, 0x0b, 0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0, 1, 0,
		0x79, 7, 0x4f, 5, 0xa0, 0, 0, 3, 8,
		0x50, 0x15, 'P', 'i', 'v', 'A', 'p', 'p', 'l', 'e', 't', ' ', 'v', '0', '.', '9', '.', '0', '/', 'R', 'S', 'a', 'D',
		0x5f, 0x50, 0x1e, 'g', 'i', 't', 'h', 'u', 'b', '.', 'c', 'o', 'm', '/', 'a', 'r', 'e', 'k', 'i', 'n', 'a', 't', 'h', '/', 'P', 'i', 'v', 'A', 'p', 'p', 'l', 'e', 't',
		0xac, 6, 0x80, 1, 3, 0x06, 1, 0,
		0xac, 6, 0x80, 1, 0x0c, 0x06, 1, 0,
		0xac, 6, 0x80, 1, 7, 0x06, 1, 0,
	}

	got, err := ParseApplicationPropertyTemplate(data)
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(got.Algorithms, []Algorithm{TripleDES, AES256, RSA2048}) {
		t.Errorf("algorithms = %x, want 03 0c 07", got.Algorithms)
	}
}

func TestParseApplicationPropertyTemplateRejectsInvalidData(t *testing.T) {
	aid := []byte{0x4f, 0x06, 0, 0, 0x10, 0, 1, 0}
	authority := []byte{0x79, 7, 0x4f, 5, 0xa0, 0, 0, 3, 8}
	valid := slices.Concat(aid, authority)

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "empty"},
		{name: "missing AID", data: authority},
		{name: "missing tag allocation authority", data: aid},
		{name: "empty AID", data: slices.Concat([]byte{0x4f, 0}, authority)},
		{name: "oversized AID", data: slices.Concat([]byte{0x4f, 17}, make([]byte, 17), authority)},
		{name: "duplicate AID", data: append(slices.Clone(valid), aid...)},
		{name: "missing authority AID", data: append(slices.Clone(aid), 0x79, 0)},
		{name: "empty authority AID", data: append(slices.Clone(aid), 0x79, 2, 0x4f, 0)},
		{name: "duplicate authority AID", data: append(slices.Clone(aid), 0x79, 6, 0x4f, 1, 1, 0x4f, 1, 2)},
		{name: "duplicate authority", data: append(slices.Clone(aid), 0x79, 3, 0x4f, 1, 1, 0x79, 3, 0x4f, 1, 2)},
		{name: "truncated authority", data: append(slices.Clone(aid), 0x79, 1, 0x4f)},
		{name: "duplicate label", data: append(slices.Clone(valid), 0x50, 0, 0x50, 0)},
		{name: "duplicate URL", data: append(slices.Clone(valid), 0x5f, 0x50, 0, 0x5f, 0x50, 0)},
		{name: "truncated field", data: append(slices.Clone(valid), 0x50, 2, 1)},
		{name: "empty algorithms", data: append(slices.Clone(valid), 0xac, 0)},
		{name: "missing algorithm OID", data: append(slices.Clone(valid), 0xac, 3, 0x80, 1, 0x27)},
		{name: "missing algorithm ID", data: append(slices.Clone(valid), 0xac, 3, 0x06, 1, 0)},
		{name: "empty algorithm ID", data: append(slices.Clone(valid), 0xac, 5, 0x80, 0, 0x06, 1, 0)},
		{name: "long algorithm ID", data: append(slices.Clone(valid), 0xac, 7, 0x80, 2, 0x27, 0x2e, 0x06, 1, 0)},
		{name: "invalid algorithm OID", data: append(slices.Clone(valid), 0xac, 6, 0x80, 1, 0x27, 0x06, 1, 1)},
		{name: "duplicate algorithm OID", data: append(slices.Clone(valid), 0xac, 9, 0x80, 1, 0x27, 0x06, 1, 0, 0x06, 1, 0)},
		{name: "truncated algorithm", data: append(slices.Clone(valid), 0xac, 1, 0x80)},
		{name: "malformed second algorithm template", data: slices.Concat(aid, authority, []byte{0xac, 6, 0x80, 1, 0x27, 0x06, 1, 0, 0xac, 3, 0x80, 1, 0x2e})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseApplicationPropertyTemplate(bertlv.Append(nil, 0x61, tc.data))
			if !errors.Is(err, ErrInvalidResponse) {
				t.Errorf("ParseApplicationPropertyTemplate error = %v, want ErrInvalidResponse", err)
			}
		})
	}

	for _, data := range [][]byte{
		{0x61, 1},
		bertlv.Append(nil, 0x53, valid),
		append(bertlv.Append(nil, 0x61, valid), 0x61, 0),
	} {
		if _, err := ParseApplicationPropertyTemplate(data); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("ParseApplicationPropertyTemplate(%x) error = %v, want ErrInvalidResponse", data, err)
		}
	}
}
