package protocol

import (
	"fmt"

	"github.com/telesma-app/piv/internal/bertlv"
)

// PINUsagePolicyFlags is the first byte of the Discovery Object's PIN Usage
// Policy (SP 800-73-5 Part 1, Sec. 3.3.2). Unknown bits are preserved.
type PINUsagePolicyFlags byte

const (
	PINUsageApplicationPIN        PINUsagePolicyFlags = 0x40
	PINUsageGlobalPIN             PINUsagePolicyFlags = 0x20
	PINUsageOCC                   PINUsagePolicyFlags = 0x10
	PINUsageVCI                   PINUsagePolicyFlags = 0x08
	PINUsageVCIWithoutPairingCode PINUsagePolicyFlags = 0x04
)

// PINPreference is the second byte of the PIN Usage Policy.
// Unknown values are preserved.
type PINPreference byte

const (
	PINPreferenceNone           PINPreference = 0x00
	PINPreferenceApplicationPIN PINPreference = 0x10
	PINPreferenceGlobalPIN      PINPreference = 0x20
)

// PINUsagePolicy contains both bytes of the card's PIN Usage Policy.
type PINUsagePolicy struct {
	Flags      PINUsagePolicyFlags
	PrimaryPIN PINPreference
}

// Discovery describes the optional PIV Discovery Object.
// AID borrows the parsed input.
type Discovery struct {
	AID            []byte
	PINUsagePolicy PINUsagePolicy
}

// EncodeDiscovery encodes a Discovery Object's content without the outer 7E
// template, for PutData (SP 800-73-5 Part 1, Sec. 3.3.2).
func EncodeDiscovery(discovery Discovery) []byte {
	data := bertlv.Append(nil, 0x4f, discovery.AID)

	return bertlv.Append(data, 0x5f2f, []byte{
		byte(discovery.PINUsagePolicy.Flags), byte(discovery.PINUsagePolicy.PrimaryPIN),
	})
}

// ParseDiscovery parses a Discovery Object's content without the outer tag 7E,
// as returned by GetData. The AID and two-byte PIN Usage Policy are mandatory;
// unknown fields are ignored.
func ParseDiscovery(data []byte) (Discovery, error) {
	var (
		discovery           Discovery
		haveAID, havePolicy bool
	)

	for len(data) > 0 {
		tag, value, rest, err := bertlv.Parse(data)
		if err != nil {
			return Discovery{}, fmt.Errorf("%w: discovery: %v", ErrInvalidResponse, err)
		}

		data = rest

		switch tag {
		case 0x4f:
			if haveAID || len(value) == 0 || len(value) > 16 {
				return Discovery{}, fmt.Errorf("%w: invalid discovery application identifier", ErrInvalidResponse)
			}

			discovery.AID, haveAID = value, true
		case 0x5f2f:
			if havePolicy || len(value) != 2 {
				return Discovery{}, fmt.Errorf("%w: invalid PIN usage policy", ErrInvalidResponse)
			}

			discovery.PINUsagePolicy = PINUsagePolicy{
				Flags: PINUsagePolicyFlags(value[0]), PrimaryPIN: PINPreference(value[1]),
			}
			havePolicy = true
		}
	}

	if !haveAID || !havePolicy {
		return Discovery{}, fmt.Errorf("%w: incomplete discovery object", ErrInvalidResponse)
	}

	return discovery, nil
}
