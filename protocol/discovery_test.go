package protocol

import (
	"bytes"
	"errors"
	"slices"
	"testing"
)

func TestEncodeDiscovery(t *testing.T) {
	aid := []byte{0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0, 1, 0}
	original := slices.Clone(aid)

	for _, test := range []struct {
		name   string
		policy PINUsagePolicy
		wire   []byte
	}{
		{
			name: "global PIN preferred",
			policy: PINUsagePolicy{
				Flags: PINUsageApplicationPIN | PINUsageGlobalPIN | PINUsageVCI, PrimaryPIN: PINPreferenceGlobalPIN,
			},
			wire: []byte{
				0x4f, 11, 0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0, 1, 0,
				0x5f, 0x2f, 2, 0x68, 0x20,
			},
		},
		{
			name: "unknown policy preserved", policy: PINUsagePolicy{Flags: 0xff, PrimaryPIN: 0x99},
			wire: []byte{
				0x4f, 11, 0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0, 1, 0,
				0x5f, 0x2f, 2, 0xff, 0x99,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := EncodeDiscovery(Discovery{AID: aid, PINUsagePolicy: test.policy})
			if !bytes.Equal(got, test.wire) {
				t.Errorf("EncodeDiscovery = %x, want %x", got, test.wire)
			}

			if !bytes.Equal(aid, original) {
				t.Error("EncodeDiscovery changed the supplied AID")
			}
		})
	}
}

func TestParseDiscovery(t *testing.T) {
	// The content of the Discovery Object shown in SP 800-73-5 Part 1,
	// Sec. 3.3.2, with Global PIN and VCI enabled and Global PIN preferred.
	data := []byte{
		0x4f, 0x0b, 0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
		0x5f, 0x2f, 0x02, 0x68, 0x20,
	}

	got, err := ParseDiscovery(data)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got.AID, data[2:13]) {
		t.Errorf("AID = %x", got.AID)
	}

	want := PINUsagePolicy{
		Flags: PINUsageApplicationPIN | PINUsageGlobalPIN | PINUsageVCI, PrimaryPIN: PINPreferenceGlobalPIN,
	}

	if got.PINUsagePolicy != want {
		t.Errorf("PIN usage policy = %+v, want %+v", got.PINUsagePolicy, want)
	}

	data[2] = 0x42

	if got.AID[0] != 0x42 {
		t.Error("parsed AID does not borrow the object")
	}
}

func TestParseDiscoveryPreservesUnknownPolicy(t *testing.T) {
	data := []byte{
		0x90, 1, 0xff,
		0x5f, 0x2f, 2, 0xff, 0x99,
		0x4f, 0x0b, 0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0, 1, 0,
	}

	got, err := ParseDiscovery(data)
	if err != nil {
		t.Fatal(err)
	}

	if got.PINUsagePolicy.Flags != 0xff || got.PINUsagePolicy.PrimaryPIN != 0x99 {
		t.Errorf("PIN usage policy = %+v, want raw ff 99", got.PINUsagePolicy)
	}
}

func TestParseDiscoveryRejectsInvalidData(t *testing.T) {
	aid := []byte{0x4f, 0x0b, 0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0, 1, 0}
	policy := []byte{0x5f, 0x2f, 2, 0x40, 0}

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "empty"},
		{name: "missing AID", data: policy},
		{name: "missing policy", data: aid},
		{name: "empty AID", data: append([]byte{0x4f, 0}, policy...)},
		{name: "oversized AID", data: append(append([]byte{0x4f, 17}, make([]byte, 17)...), policy...)},
		{name: "duplicate AID", data: slices.Concat(aid, aid, policy)},
		{name: "empty policy", data: append(slices.Clone(aid), 0x5f, 0x2f, 0)},
		{name: "short policy", data: append(slices.Clone(aid), 0x5f, 0x2f, 1, 0x40)},
		{name: "long policy", data: append(slices.Clone(aid), 0x5f, 0x2f, 3, 0x40, 0, 0)},
		{name: "duplicate policy", data: slices.Concat(aid, policy, policy)},
		{name: "truncated field", data: append(slices.Concat(aid, policy), 0x90, 1)},
		{name: "unexpected outer template", data: append([]byte{0x7e, 18}, slices.Concat(aid, policy)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseDiscovery(tc.data); !errors.Is(err, ErrInvalidResponse) {
				t.Errorf("ParseDiscovery error = %v, want ErrInvalidResponse", err)
			}
		})
	}
}
