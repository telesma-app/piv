package iso7816

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	baseiso7816 "github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	pivtransport "github.com/telesma-app/piv/transport"
)

var (
	selectAPDU     = []byte{0x00, 0xa4, 0x04, 0x00, 0x09, 0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x00}
	selectResponse = []byte{
		0x61, 0x11,
		0x4f, 0x06, 0, 0, 0x10, 0, 1, 0,
		0x79, 0x07, 0x4f, 0x05, 0xa0, 0, 0, 3, 8,
		0x90, 0,
	}
)

type exchange struct {
	request  []byte
	response []byte
	err      error
	after    func()
}

type fakeCard struct {
	t          testing.TB
	exchanges  []exchange
	closeCalls int
	closeErr   error
}

func (c *fakeCard) Transmit(ctx context.Context, apdu []byte) ([]byte, error) {
	c.t.Helper()

	if len(c.exchanges) == 0 {
		c.t.Fatalf("unexpected APDU: %x", apdu)
	}

	next := c.exchanges[0]

	c.exchanges = c.exchanges[1:]
	if !bytes.Equal(apdu, next.request) {
		c.t.Fatalf("APDU = %x, want %x", apdu, next.request)
	}

	if next.after != nil {
		next.after()
	}

	return next.response, next.err
}

func (c *fakeCard) Close() error {
	c.closeCalls++
	return c.closeErr
}

func newTransport(t testing.TB, exchanges ...exchange) (*Transport, *fakeCard) {
	t.Helper()
	card := &fakeCard{
		t: t,
		exchanges: append([]exchange{{
			request: selectAPDU, response: selectResponse,
		}}, exchanges...),
	}

	device, err := Open(context.Background(), card)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if err := device.Close(); err != nil && card.closeErr == nil {
			t.Error(err)
		}
	})

	return device, card
}

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

func TestSecureExchangeCollectsResponseUsingPlainCLA(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cla      byte
		encoding baseiso7816.Encoding
	}{
		{name: "short", cla: 0x04, encoding: baseiso7816.EncodingShort},
		{name: "extended", cla: 0x04, encoding: baseiso7816.EncodingExtended},
		{name: "vendor short", cla: 0x84, encoding: baseiso7816.EncodingShort},
		{name: "vendor extended", cla: 0x84, encoding: baseiso7816.EncodingExtended},
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

func TestExchangeStopsAfterRejectedFragment(t *testing.T) {
	data := bytes.Repeat([]byte{0xab}, 256)
	device, card := newTransport(t, exchange{
		request: append([]byte{0x10, 0xdb, 0x3f, 0xff, 0xff}, data[:255]...), response: []byte{0x69, 0x82},
	})
	_, err := device.Exchange(t.Context(), baseiso7816.Command{INS: 0xdb, P1: 0x3f, P2: 0xff, Data: data})

	var apduError *baseiso7816.APDUError
	if !errors.As(err, &apduError) || apduError.StatusWord() != 0x6982 {
		t.Fatalf("Exchange = %v, want APDU error 6982", err)
	}

	var invalidated *pivtransport.DeviceInvalidatedError
	if errors.As(err, &invalidated) || card.closeCalls != 0 {
		t.Fatal("rejected fragment invalidated the card")
	}

	card.exchanges = append(card.exchanges, exchange{
		request: []byte{0x00, 0x20, 0x00, 0x80}, response: []byte{0x63, 0xc3},
	})

	response, err := device.Exchange(t.Context(), baseiso7816.Command{INS: 0x20, P2: 0x80})
	if err != nil || response.Status != 0x63c3 {
		t.Fatalf("Exchange after rejection = %s, %v; want status 63c3", response.Status, err)
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

func TestOpenFailurePreservesCallerOwnership(t *testing.T) {
	for _, test := range []struct {
		name     string
		response []byte
		err      error
		want     error
	}{
		{name: "missing application", response: []byte{0x6a, 0x82}},
		{name: "malformed response", response: []byte{0x90}},
		{name: "missing application properties", response: []byte{0x61, 0, 0x90, 0}, want: protocol.ErrInvalidResponse},
		{name: "I/O failure", err: io.ErrClosedPipe},
	} {
		t.Run(test.name, func(t *testing.T) {
			card := &fakeCard{t: t, exchanges: []exchange{{request: selectAPDU, response: test.response, err: test.err}}}

			device, err := Open(t.Context(), card)
			if device != nil || err == nil {
				t.Fatalf("Open = %v, %v; want failure", device, err)
			}

			if test.want != nil && !errors.Is(err, test.want) {
				t.Errorf("Open = %v, want %v", err, test.want)
			}

			if card.closeCalls != 0 {
				t.Error("failed Open closed caller's card")
			}
		})
	}
}

func TestPreCanceledExchangePreservesCard(t *testing.T) {
	device, card := newTransport(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := device.Exchange(ctx, baseiso7816.Command{INS: 0x20, P2: 0x80})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Exchange = %v, want context cancellation", err)
	}

	var invalidated *pivtransport.DeviceInvalidatedError
	if errors.As(err, &invalidated) || card.closeCalls != 0 {
		t.Fatal("pre-cancellation invalidated card")
	}
}

type gatedCard struct {
	requests chan byte
	release  chan struct{}
	closed   chan struct{}
}

func (c *gatedCard) Transmit(ctx context.Context, apdu []byte) ([]byte, error) {
	if bytes.Equal(apdu, selectAPDU) {
		return selectResponse, nil
	}

	select {
	case c.requests <- apdu[1]:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, io.ErrClosedPipe
	}

	select {
	case <-c.release:
		return []byte{0x90, 0x00}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, io.ErrClosedPipe
	}
}

func (c *gatedCard) Close() error {
	close(c.closed)
	return nil
}

func TestQueuedExchangeCancellationPreservesActiveCard(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctx  func(context.Context) (context.Context, context.CancelFunc)
		want error
	}{
		{name: "canceled", ctx: context.WithCancel, want: context.Canceled},
		{
			name: "deadline",
			ctx: func(parent context.Context) (context.Context, context.CancelFunc) {
				return context.WithTimeout(parent, 10*time.Millisecond)
			},
			want: context.DeadlineExceeded,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			card := &gatedCard{
				requests: make(chan byte, 1),
				release:  make(chan struct{}),
				closed:   make(chan struct{}),
			}

			device, err := Open(t.Context(), card)
			if err != nil {
				t.Fatal(err)
			}

			active := make(chan error, 1)

			done := make(chan struct{})
			go func() {
				defer close(done)

				_, err := device.Exchange(t.Context(), baseiso7816.Command{INS: 0x20, P2: 0x80})
				active <- err
			}()

			t.Cleanup(func() {
				_ = device.Close()

				receive(t, done, "active Exchange did not stop")
			})

			if instruction := receive(t, card.requests, "active Exchange did not start"); instruction != 0x20 {
				t.Fatalf("instruction = %02x, want 20", instruction)
			}

			ctx, cancel := tc.ctx(t.Context())
			defer cancel()

			queued := make(chan error, 1)

			go func() {
				_, err := device.Exchange(ctx, baseiso7816.Command{INS: 0xcb, P1: 0x3f, P2: 0xff, Le: 256})
				queued <- err
			}()

			if tc.want == context.Canceled {
				cancel()
			}

			err = receive(t, queued, "queued Exchange waited for active Exchange after cancellation")

			var invalidated *pivtransport.DeviceInvalidatedError
			if !errors.Is(err, tc.want) || errors.As(err, &invalidated) {
				t.Fatalf("queued Exchange = %v, want cancellation without invalidation", err)
			}

			select {
			case <-card.closed:
				t.Fatal("queued cancellation closed active card")
			default:
			}

			select {
			case instruction := <-card.requests:
				t.Fatalf("queued Exchange transmitted instruction %02x", instruction)
			default:
			}

			close(card.release)

			if err := receive(t, active, "active Exchange did not finish"); err != nil {
				t.Fatal(err)
			}

			response, err := device.Exchange(t.Context(), baseiso7816.Command{INS: 0x84, Le: 256})
			if err != nil || response.Status != 0x9000 {
				t.Fatalf("Exchange after queued cancellation = %s, %v; want success", response.Status, err)
			}

			if instruction := receive(t, card.requests, "reused card did not transmit"); instruction != 0x84 {
				t.Errorf("instruction = %02x, want 84", instruction)
			}
		})
	}
}

type delayedCloseCard struct {
	gatedCard
	closeStarted chan struct{}
	finishClose  chan struct{}
}

func (c *delayedCloseCard) Close() error {
	close(c.closeStarted)
	<-c.finishClose

	return c.gatedCard.Close()
}

func TestCloseReleasesQueuedExchangeBeforeCardCloseCompletes(t *testing.T) {
	card := &delayedCloseCard{
		gatedCard: gatedCard{
			requests: make(chan byte, 1),
			release:  make(chan struct{}),
			closed:   make(chan struct{}),
		},
		closeStarted: make(chan struct{}),
		finishClose:  make(chan struct{}),
	}

	device, err := Open(t.Context(), card)
	if err != nil {
		t.Fatal(err)
	}

	activeCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	active := make(chan error, 1)

	go func() {
		_, err := device.Exchange(activeCtx, baseiso7816.Command{INS: 0x20, P2: 0x80})
		active <- err
	}()

	closed := make(chan error, 1)

	t.Cleanup(func() {
		close(card.finishClose)

		_ = device.Close()

		if err := receive(t, closed, "Close did not finish after card was released"); err != nil {
			t.Error(err)
		}

		if err := receive(t, active, "active Exchange did not stop after Close"); !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("active Exchange = %v, want closed pipe", err)
		}
	})
	receive(t, card.requests, "active Exchange did not start")

	queued := make(chan error, 1)

	go func() {
		_, err := device.Exchange(t.Context(), baseiso7816.Command{INS: 0xcb, P1: 0x3f, P2: 0xff, Le: 256})
		queued <- err
	}()
	go func() { closed <- device.Close() }()

	receive(t, card.closeStarted, "Close waited for active Exchange")

	err = receive(t, queued, "queued Exchange waited for card Close to complete")

	var invalidated *pivtransport.DeviceInvalidatedError
	if !errors.Is(err, io.ErrClosedPipe) || errors.As(err, &invalidated) {
		t.Fatalf("queued Exchange = %v, want closed pipe without invalidation", err)
	}

	select {
	case instruction := <-card.requests:
		t.Fatalf("queued Exchange transmitted instruction %02x", instruction)
	default:
	}
}

func TestExchangeAfterCloseDoesNotTransmit(t *testing.T) {
	device, card := newTransport(t)
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}

	_, err := device.Exchange(t.Context(), baseiso7816.Command{INS: 0x20, P2: 0x80})

	var invalidated *pivtransport.DeviceInvalidatedError
	if !errors.Is(err, io.ErrClosedPipe) || errors.As(err, &invalidated) {
		t.Fatalf("Exchange = %v, want closed pipe without invalidation", err)
	}

	if card.closeCalls != 1 {
		t.Errorf("Close calls = %d, want 1", card.closeCalls)
	}
}

func TestInterruptedChainClosesOwnedCard(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	data := bytes.Repeat([]byte{0xab}, 256)
	device, card := newTransport(t, exchange{
		request: append([]byte{0x10, 0xdb, 0x3f, 0xff, 0xff}, data[:255]...), response: []byte{0x90, 0x00}, after: cancel,
	})
	_, err := device.Exchange(ctx, baseiso7816.Command{INS: 0xdb, P1: 0x3f, P2: 0xff, Data: data})

	var invalidated *pivtransport.DeviceInvalidatedError
	if !errors.Is(err, context.Canceled) || !errors.As(err, &invalidated) {
		t.Fatalf("Exchange = %v, want invalidated cancellation", err)
	}

	if card.closeCalls != 1 {
		t.Errorf("Close calls = %d, want 1", card.closeCalls)
	}
}

func TestInterruptedGetResponseClosesOwnedCard(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	device, card := newTransport(t, exchange{
		request: []byte{0x00, 0xcb, 0x3f, 0xff, 0x00}, response: []byte{0x53, 0x61, 0x01}, after: cancel,
	})
	_, err := device.Exchange(ctx, baseiso7816.Command{INS: 0xcb, P1: 0x3f, P2: 0xff, Le: 256})

	var invalidated *pivtransport.DeviceInvalidatedError
	if !errors.Is(err, context.Canceled) || !errors.As(err, &invalidated) {
		t.Fatalf("Exchange = %v, want invalidated cancellation", err)
	}

	if card.closeCalls != 1 {
		t.Errorf("Close calls = %d, want 1", card.closeCalls)
	}
}

func TestUnexpectedIntermediateResponseInvalidatesCard(t *testing.T) {
	for _, response := range [][]byte{{0x01, 0x90, 0x00}, {0x61, 0x01}, {0x9f, 0x01}} {
		data := bytes.Repeat([]byte{0xab}, 256)
		device, card := newTransport(t, exchange{
			request: append([]byte{0x10, 0xdb, 0x3f, 0xff, 0xff}, data[:255]...), response: response,
		})
		_, err := device.Exchange(t.Context(), baseiso7816.Command{INS: 0xdb, P1: 0x3f, P2: 0xff, Data: data})

		var invalidated *pivtransport.DeviceInvalidatedError
		if !errors.Is(err, baseiso7816.ErrInvalidResponse) || !errors.As(err, &invalidated) {
			t.Fatalf("response %x: Exchange = %v, want invalid response and invalidation", response, err)
		}

		if card.closeCalls != 1 {
			t.Errorf("Close calls = %d, want 1", card.closeCalls)
		}
	}
}

func TestTerminalResponsePreservesCardAfterConcurrentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	device, card := newTransport(t, exchange{
		request: []byte{0x00, 0x20, 0x00, 0x80}, response: []byte{0x63, 0xc3}, after: cancel,
	})

	response, err := device.Exchange(ctx, baseiso7816.Command{INS: 0x20, P2: 0x80})
	if err != nil || response.Status != 0x63c3 {
		t.Fatalf("Exchange = %s, %v; want terminal status 63c3", response.Status, err)
	}

	if card.closeCalls != 0 {
		t.Fatal("terminal response invalidated the card")
	}

	card.exchanges = append(card.exchanges, exchange{
		request: []byte{0x00, 0x20, 0x00, 0x80}, response: []byte{0x63, 0xc3},
	})

	response, err = device.Exchange(t.Context(), baseiso7816.Command{INS: 0x20, P2: 0x80})
	if err != nil || response.Status != 0x63c3 {
		t.Fatalf("Exchange after cancellation = %s, %v; want status 63c3", response.Status, err)
	}
}

func TestExchangeRejectsOversizedResponse(t *testing.T) {
	response := append(bytes.Repeat([]byte{0xab}, 65537), 0x90, 0x00)
	device, card := newTransport(t, exchange{
		request: []byte{0x00, 0xcb, 0x3f, 0xff, 0x00}, response: response,
	})
	_, err := device.Exchange(t.Context(), baseiso7816.Command{INS: 0xcb, P1: 0x3f, P2: 0xff, Le: 256})

	var invalidated *pivtransport.DeviceInvalidatedError
	if !errors.Is(err, baseiso7816.ErrResponseTooLarge) || !errors.As(err, &invalidated) {
		t.Fatalf("Exchange = %v, want oversized response and invalidation", err)
	}

	if card.closeCalls != 1 {
		t.Errorf("Close calls = %d, want 1", card.closeCalls)
	}
}

func TestExchangeFailureInvalidatesOwnedCard(t *testing.T) {
	for _, test := range []struct {
		name     string
		response []byte
		err      error
	}{
		{name: "malformed response", response: []byte{0x90}},
		{name: "I/O failure", err: io.ErrClosedPipe},
	} {
		t.Run(test.name, func(t *testing.T) {
			device, card := newTransport(t, exchange{request: []byte{0x00, 0x20, 0x00, 0x80}, response: test.response, err: test.err})
			_, err := device.Exchange(t.Context(), baseiso7816.Command{INS: 0x20, P2: 0x80})

			var invalidated *pivtransport.DeviceInvalidatedError
			if !errors.As(err, &invalidated) {
				t.Fatalf("Exchange = %v, want invalidation", err)
			}

			if test.err != nil && !errors.Is(err, test.err) {
				t.Errorf("Exchange = %v, lost cause %v", err, test.err)
			}

			if card.closeCalls != 1 {
				t.Errorf("Close calls = %d, want 1", card.closeCalls)
			}
		})
	}
}

func TestClosePreservesTypedErrorAndRunsOnce(t *testing.T) {
	device, card := newTransport(t)
	card.closeErr = io.ErrClosedPipe

	for range 2 {
		err := device.Close()

		var ioErr *pivtransport.IOError
		if !errors.As(err, &ioErr) || ioErr.Operation != pivtransport.IOClose || !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("Close = %v, want typed close failure", err)
		}
	}

	if card.closeCalls != 1 {
		t.Errorf("Close calls = %d, want 1", card.closeCalls)
	}
}

type blockingCard struct {
	started chan struct{}
	closed  chan struct{}
}

func (c *blockingCard) Transmit(ctx context.Context, apdu []byte) ([]byte, error) {
	if bytes.Equal(apdu, selectAPDU) {
		return selectResponse, nil
	}

	close(c.started)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, io.ErrClosedPipe
	}
}

func (c *blockingCard) Close() error {
	close(c.closed)
	return nil
}

func TestCloseInterruptsExchange(t *testing.T) {
	card := &blockingCard{started: make(chan struct{}), closed: make(chan struct{})}

	device, err := Open(t.Context(), card)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = device.Close() })

	result := make(chan error, 1)

	go func() {
		_, err := device.Exchange(t.Context(), baseiso7816.Command{INS: 0x20, P2: 0x80})
		result <- err
	}()

	receive(t, card.started, "Exchange did not start")

	closed := make(chan error, 1)
	go func() { closed <- device.Close() }()

	if err := receive(t, closed, "Close waited for Exchange mutex"); err != nil {
		t.Fatal(err)
	}

	if err := receive(t, result, "Exchange did not stop after Close"); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Exchange = %v, want I/O failure", err)
	}
}

func receive[T any](t testing.TB, ch <-chan T, failure string) T {
	t.Helper()

	select {
	case value := <-ch:
		return value
	case <-time.After(time.Second):
		t.Fatal(failure)

		var zero T

		return zero
	}
}
