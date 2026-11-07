package card

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/telesma-app/iso7816"
)

type exchangeStep struct {
	command  []byte
	response iso7816.Response
	err      error
	after    func()
}

type scriptTransport struct {
	t          testing.TB
	steps      []exchangeStep
	calls      int
	closeCalls int
	closeErr   error
}

func newDevice(t testing.TB, steps ...exchangeStep) (*Device, *scriptTransport) {
	t.Helper()
	raw := &scriptTransport{t: t, steps: steps}
	d := New(raw)

	t.Cleanup(func() {
		_ = d.Close()

		if raw.calls != len(raw.steps) {
			t.Errorf("exchange count = %d, want %d", raw.calls, len(raw.steps))
		}
	})

	return d, raw
}

func (s *scriptTransport) Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	s.t.Helper()

	if s.calls >= len(s.steps) {
		s.t.Errorf("unexpected exchange: %+v", command)
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	step := s.steps[s.calls]
	s.calls++

	raw, err := command.MarshalBinary()
	if err != nil {
		s.t.Error(err)
		return iso7816.Response{}, err
	}

	if !bytes.Equal(raw, step.command) {
		s.t.Errorf("APDU = %x, want %x", raw, step.command)
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	if step.after != nil {
		step.after()
	}

	return step.response, step.err
}

func (s *scriptTransport) Close() error {
	s.closeCalls++
	return s.closeErr
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
