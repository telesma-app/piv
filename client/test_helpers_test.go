package client

import (
	"bytes"
	"context"
	"testing"

	"github.com/telesma-app/iso7816"
)

type exchangeStep struct {
	command  []byte
	response iso7816.Response
	err      error
}

type scriptTransport struct {
	t     *testing.T
	steps []exchangeStep
	calls int
}

func newScript(t *testing.T, steps ...exchangeStep) *scriptTransport {
	t.Helper()
	script := &scriptTransport{t: t, steps: steps}
	t.Cleanup(func() {
		if script.calls != len(steps) {
			t.Errorf("exchange count = %d, want %d", script.calls, len(steps))
		}
	})

	return script
}

func (s *scriptTransport) Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	s.t.Helper()

	if s.calls >= len(s.steps) {
		s.t.Fatal("unexpected exchange")
	}

	step := s.steps[s.calls]
	s.calls++

	raw, err := command.MarshalBinary()
	if err != nil {
		s.t.Fatal(err)
	}

	if !bytes.Equal(raw, step.command) {
		s.t.Fatalf("APDU = %x, want %x", raw, step.command)
	}

	return step.response, step.err
}
