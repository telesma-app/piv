package iso7816

import (
	"bytes"
	"errors"
	"testing"

	baseiso7816 "github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	pivtransport "github.com/telesma-app/piv/transport"
)

func TestSelectReturnsApplicationTemplate(t *testing.T) {
	card := &fakeCard{t: t, exchanges: []exchange{{
		request: selectAPDU, response: selectResponse,
	}}}

	properties, err := Select(t.Context(), card)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(properties.AID, []byte{0, 0, 0x10, 0, 1, 0}) {
		t.Errorf("application identifier = %x", properties.AID)
	}

	if !bytes.Equal(properties.TagAllocationAuthorityAID, []byte{0xa0, 0, 0, 3, 8}) {
		t.Errorf("tag allocation authority = %x", properties.TagAllocationAuthorityAID)
	}

	if card.closeCalls != 0 {
		t.Error("Select closed borrowed card")
	}
}

func TestSelectRejectsMalformedSuccessfulApplicationTemplate(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response []byte
	}{
		{name: "missing template", response: []byte{0x90, 0}},
		{name: "missing mandatory identifiers", response: []byte{0x61, 0, 0x90, 0}},
		{name: "missing authority", response: []byte{0x61, 3, 0x4f, 1, 0xaa, 0x90, 0}},
		{name: "truncated template", response: []byte{0x61, 4, 0x4f, 1, 0xaa, 0x90, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			card := &fakeCard{t: t, exchanges: []exchange{{request: selectAPDU, response: tc.response}}}

			_, err := Select(t.Context(), card)
			if !errors.Is(err, protocol.ErrInvalidResponse) {
				t.Fatalf("Select = %v, want invalid application property template", err)
			}

			var invalidated *pivtransport.DeviceInvalidatedError
			if errors.As(err, &invalidated) || card.closeCalls != 0 {
				t.Fatal("template parsing failure invalidated or closed borrowed card")
			}
		})
	}
}

func TestExchangeReturnsUninterpretedStatus(t *testing.T) {
	card := &fakeCard{t: t, exchanges: []exchange{{
		request: []byte{0x00, 0x20, 0x00, 0x80}, response: []byte{0x63, 0xc3},
	}}}

	response, err := Exchange(t.Context(), card, baseiso7816.Command{INS: 0x20, P2: 0x80})
	if err != nil {
		t.Fatal(err)
	}

	if response.Status != 0x63c3 {
		t.Errorf("status = %s, want 63c3", response.Status)
	}
}

func TestExchangeCollectsGetResponse(t *testing.T) {
	card := &fakeCard{t: t, exchanges: []exchange{
		{request: []byte{0x00, 0xcb, 0x3f, 0xff, 0x05, 0x5c, 0x03, 0x5f, 0xc1, 0x05, 0x00}, response: []byte{0x53, 0x03, 0x61, 0x03}},
		{request: []byte{0x00, 0xc0, 0x00, 0x00, 0x03}, response: []byte{0x70, 0x01, 0x01, 0x90, 0x00}},
	}}

	response, err := Exchange(t.Context(), card, baseiso7816.Command{
		INS: 0xcb, P1: 0x3f, P2: 0xff, Data: []byte{0x5c, 0x03, 0x5f, 0xc1, 0x05}, Le: 256,
	})
	if err != nil {
		t.Fatal(err)
	}

	if response.Status != 0x9000 || !bytes.Equal(response.Data, []byte{0x53, 0x03, 0x70, 0x01, 0x01}) {
		t.Errorf("response = %x, %s", response.Data, response.Status)
	}

	if len(card.exchanges) != 0 {
		t.Errorf("remaining exchanges = %d", len(card.exchanges))
	}
}

func TestExchangeChainsShortAPDUs(t *testing.T) {
	data := bytes.Repeat([]byte{0xab}, 600)
	card := &fakeCard{t: t, exchanges: []exchange{
		{request: append([]byte{0x10, 0x87, 0x07, 0x9a, 0xff}, data[:255]...), response: []byte{0x90, 0x00}},
		{request: append([]byte{0x10, 0x87, 0x07, 0x9a, 0xff}, data[255:510]...), response: []byte{0x90, 0x00}},
		{request: append(append([]byte{0x00, 0x87, 0x07, 0x9a, 0x5a}, data[510:]...), 0x00), response: []byte{0x7c, 0x00, 0x90, 0x00}},
	}}

	response, err := Exchange(t.Context(), card, baseiso7816.Command{
		INS: 0x87, P1: 0x07, P2: 0x9a, Data: data, Le: 256,
	})
	if err != nil {
		t.Fatal(err)
	}

	if response.Status != 0x9000 || !bytes.Equal(response.Data, []byte{0x7c, 0x00}) {
		t.Errorf("response = %x, %s", response.Data, response.Status)
	}

	if len(card.exchanges) != 0 {
		t.Errorf("remaining exchanges = %d", len(card.exchanges))
	}
}

func TestExchangeHonorsExplicitExtendedEncodingWithoutChaining(t *testing.T) {
	data := bytes.Repeat([]byte{0xab}, 600)
	request := append([]byte{0x00, 0x87, 0x07, 0x9a, 0x00, 0x02, 0x58}, data...)
	request = append(request, 0x01, 0x00)
	card := &fakeCard{t: t, exchanges: []exchange{
		{request: request, response: []byte{0x7c, 0x00, 0x90, 0x00}},
	}}

	response, err := Exchange(t.Context(), card, baseiso7816.Command{
		INS: 0x87, P1: 0x07, P2: 0x9a, Data: data, Le: 256, Encoding: baseiso7816.EncodingExtended,
	})
	if err != nil {
		t.Fatal(err)
	}

	if response.Status != 0x9000 || !bytes.Equal(response.Data, []byte{0x7c, 0x00}) {
		t.Errorf("response = %x, %s", response.Data, response.Status)
	}

	if len(card.exchanges) != 0 {
		t.Errorf("remaining exchanges = %d, want one complete extended APDU", len(card.exchanges))
	}
}

func TestExchangeCollectsResponseUsingPlainCLA(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cla      byte
		encoding baseiso7816.Encoding
	}{
		{name: "short", cla: 0x04, encoding: baseiso7816.EncodingShort},
		{name: "extended", cla: 0x04, encoding: baseiso7816.EncodingExtended},
		{name: "vendor short", cla: 0x84, encoding: baseiso7816.EncodingShort},
		{name: "vendor extended", cla: 0x84, encoding: baseiso7816.EncodingExtended},
		{name: "proprietary short", cla: 0x80, encoding: baseiso7816.EncodingShort},
		{name: "proprietary extended", cla: 0x80, encoding: baseiso7816.EncodingExtended},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := bytes.Repeat([]byte{0xa5}, 24)
			request := append([]byte{tc.cla, 0xcb, 0x3f, 0xff, 24}, data...)
			request = append(request, 0)

			if tc.encoding == baseiso7816.EncodingExtended {
				request = append([]byte{tc.cla, 0xcb, 0x3f, 0xff, 0, 0, 24}, data...)
				request = append(request, 0x01, 0x00)
			}

			card := &fakeCard{t: t, exchanges: []exchange{
				{request: request, response: []byte{1, 2, 0x61, 4}},
				{request: []byte{0x00, 0xc0, 0, 0, 4}, response: []byte{3, 4, 0x61, 2}},
				{request: []byte{0x00, 0xc0, 0, 0, 2}, response: []byte{5, 6, 0x90, 0}},
			}}

			response, err := Exchange(t.Context(), card, baseiso7816.Command{
				CLA: tc.cla, INS: 0xcb, P1: 0x3f, P2: 0xff, Data: data, Le: 256, Encoding: tc.encoding,
			})
			if err != nil {
				t.Fatal(err)
			}

			if response.Status != 0x9000 || !bytes.Equal(response.Data, []byte{1, 2, 3, 4, 5, 6}) {
				t.Errorf("collected response = %x, %s", response.Data, response.Status)
			}

			if len(card.exchanges) != 0 {
				t.Errorf("remaining exchanges = %d", len(card.exchanges))
			}
		})
	}
}

func TestSecureShortExchangeChainsProtectedBodyBeforePlainGetResponse(t *testing.T) {
	data := bytes.Repeat([]byte{0xab}, 600)
	card := &fakeCard{t: t, exchanges: []exchange{
		{request: append([]byte{0x14, 0x87, 0x07, 0x9c, 0xff}, data[:255]...), response: []byte{0x90, 0x00}},
		{request: append([]byte{0x14, 0x87, 0x07, 0x9c, 0xff}, data[255:510]...), response: []byte{0x90, 0x00}},
		{request: append(append([]byte{0x04, 0x87, 0x07, 0x9c, 0x5a}, data[510:]...), 0), response: []byte{1, 2, 0x61, 3}},
		{request: []byte{0x00, 0xc0, 0, 0, 3}, response: []byte{3, 4, 5, 0x90, 0}},
	}}

	response, err := Exchange(t.Context(), card, baseiso7816.Command{
		CLA: 0x04, INS: 0x87, P1: 0x07, P2: 0x9c, Data: data, Le: 256, Encoding: baseiso7816.EncodingShort,
	})
	if err != nil {
		t.Fatal(err)
	}

	if response.Status != 0x9000 || !bytes.Equal(response.Data, []byte{1, 2, 3, 4, 5}) {
		t.Errorf("collected response = %x, %s", response.Data, response.Status)
	}

	if len(card.exchanges) != 0 {
		t.Errorf("remaining exchanges = %d", len(card.exchanges))
	}
}

func TestExchangeCollectsResponseAfterChainedCommand(t *testing.T) {
	data := bytes.Repeat([]byte{0xab}, 256)
	card := &fakeCard{t: t, exchanges: []exchange{
		{request: append([]byte{0x10, 0x87, 0x07, 0x9a, 0xff}, data[:255]...), response: []byte{0x90, 0x00}},
		{request: []byte{0x00, 0x87, 0x07, 0x9a, 0x01, 0xab, 0x00}, response: []byte{0x7c, 0x02, 0x61, 0x02}},
		{request: []byte{0x00, 0xc0, 0x00, 0x00, 0x02}, response: []byte{0x82, 0x00, 0x90, 0x00}},
	}}

	response, err := Exchange(t.Context(), card, baseiso7816.Command{
		INS: 0x87, P1: 0x07, P2: 0x9a, Data: data, Le: 256,
	})
	if err != nil {
		t.Fatal(err)
	}

	if response.Status != 0x9000 || !bytes.Equal(response.Data, []byte{0x7c, 0x02, 0x82, 0x00}) {
		t.Errorf("response = %x, %s", response.Data, response.Status)
	}

	if len(card.exchanges) != 0 {
		t.Errorf("remaining exchanges = %d", len(card.exchanges))
	}
}
