package card

import (
	"errors"
	"io"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

type secureMessagingTransport struct {
	*scriptTransport
	active bool
}

func (s *secureMessagingTransport) PIVSecureMessaging() bool {
	return s.active
}

func newSMDevice(t *testing.T, steps ...exchangeStep) (*Device, *scriptTransport) {
	t.Helper()

	raw := &scriptTransport{t: t, steps: steps}
	d := New(&secureMessagingTransport{scriptTransport: raw, active: true})

	t.Cleanup(func() {
		_ = d.Close()

		if raw.calls != len(steps) {
			t.Errorf("exchange count = %d, want %d", raw.calls, len(steps))
		}
	})

	return d, raw
}

func vciDiscovery(flags protocol.PINUsagePolicyFlags) exchangeStep {
	return exchangeStep{
		command: []byte{0, 0xcb, 0x3f, 0xff, 3, 0x5c, 1, 0x7e, 0},
		response: iso7816.Response{Status: 0x9000, Data: []byte{
			0x7e, 0x12, 0x4f, 0x0b, 0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0, 1, 0,
			0x5f, 0x2f, 2, byte(flags), 0,
		}},
	}
}

func TestPairingAndVCIAreExplicitOperations(t *testing.T) {
	d, _ := newSMDevice(t,
		exchangeStep{
			command:  []byte{0, 0x20, 0, 0x98, 8, '6', '5', '1', '3', '5', '2', '7', '5'},
			response: iso7816.Response{Status: 0x9000},
		},
		vciDiscovery(protocol.PINUsageVCI),
		exchangeStep{command: []byte{0, 0x20, 0, 0x98}, response: iso7816.Response{Status: 0x9000}},
	)

	if err := d.VerifyPairingCode(t.Context(), "65135275"); err != nil {
		t.Fatal(err)
	}

	if err := d.CheckVCI(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestCheckVCIWithoutPairing(t *testing.T) {
	d, _ := newSMDevice(t, vciDiscovery(protocol.PINUsageVCI|protocol.PINUsageVCIWithoutPairingCode))
	if err := d.CheckVCI(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestCheckVCIRequiresNISTSecureMessaging(t *testing.T) {
	t.Run("plaintext", func(t *testing.T) {
		d, _ := newDevice(t)
		if err := d.CheckVCI(t.Context()); !errors.Is(err, ErrSecureMessagingRequired) {
			t.Fatalf("CheckVCI = %v, want secure messaging required", err)
		}
	})

	t.Run("inactive", func(t *testing.T) {
		d, raw := newSMDevice(t)

		d.transport.(*secureMessagingTransport).active = false
		if err := d.CheckVCI(t.Context()); !errors.Is(err, ErrSecureMessagingRequired) {
			t.Fatalf("CheckVCI = %v, want secure messaging required", err)
		}

		if raw.calls != 0 {
			t.Fatal("inactive secure messaging performed I/O")
		}
	})
}

func TestCheckVCIRequiresPolicy(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags protocol.PINUsagePolicyFlags
	}{
		{name: "application PIN only", flags: protocol.PINUsageApplicationPIN},
		{name: "without-pairing bit alone", flags: protocol.PINUsageVCIWithoutPairingCode},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _ := newSMDevice(t, vciDiscovery(tc.flags))
			if err := d.CheckVCI(t.Context()); !errors.Is(err, ErrVCINotSupported) {
				t.Fatalf("CheckVCI = %v, want VCI unsupported", err)
			}
		})
	}
}

func TestCheckVCISerializesPolicyAndPairingCheck(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started, proceed := make(chan struct{}), make(chan struct{})

		release := sync.OnceFunc(func() { close(proceed) })
		defer release()

		discovery := vciDiscovery(protocol.PINUsageVCI)
		discovery.after = func() {
			close(started)
			<-proceed
		}

		d, raw := newSMDevice(t,
			discovery,
			exchangeStep{command: []byte{0, 0x20, 0, 0x98}, response: iso7816.Response{Status: 0x9000}},
			exchangeStep{command: []byte{0, 0x20, 0xff, 0x98}, response: iso7816.Response{Status: 0x9000}},
		)
		vciErr, resetErr := make(chan error, 1), make(chan error, 1)
		vciDone := make(chan struct{})

		go func() {
			defer close(vciDone)

			vciErr <- d.CheckVCI(t.Context())
		}()

		defer func() {
			release()
			receive(t, vciDone, "VCI worker did not stop after release")
		}()

		receive(t, started, "VCI workflow did not start reading discovery")

		resetDone := make(chan struct{})

		go func() {
			defer close(resetDone)

			resetErr <- d.ResetSecurityStatus(t.Context(), protocol.PairingCode)
		}()

		defer func() {
			release()
			receive(t, resetDone, "reset worker did not stop after release")
		}()

		synctest.Wait()

		select {
		case err := <-resetErr:
			t.Fatalf("reset completed during the VCI workflow: %v", err)
		default:
		}

		if raw.calls != 1 {
			t.Fatalf("queued operation performed I/O during VCI workflow: %d exchanges", raw.calls)
		}

		release()

		if err := receive(t, vciErr, "VCI workflow did not finish after release"); err != nil {
			t.Fatal(err)
		}

		if err := receive(t, resetErr, "queued reset did not finish after VCI"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCheckVCIPreservesCardErrors(t *testing.T) {
	for _, status := range []iso7816.StatusWord{0x6a82, 0x6982} {
		t.Run(status.String(), func(t *testing.T) {
			step := vciDiscovery(0)
			step.response = iso7816.Response{Status: status}
			d, _ := newSMDevice(t, step)

			err := d.CheckVCI(t.Context())

			var apduError *iso7816.APDUError
			if !errors.As(err, &apduError) || apduError.StatusWord() != status {
				t.Fatalf("CheckVCI = %v, want APDU status %s", err, status)
			}
		})
	}
}

func TestCheckVCIReadsCurrentPairingStatus(t *testing.T) {
	d, _ := newSMDevice(t,
		vciDiscovery(protocol.PINUsageVCI),
		exchangeStep{command: []byte{0, 0x20, 0, 0x98}, response: iso7816.Response{Status: 0x9000}},
		exchangeStep{command: []byte{0, 0x20, 0xff, 0x98}, response: iso7816.Response{Status: 0x9000}},
		vciDiscovery(protocol.PINUsageVCI),
		exchangeStep{command: []byte{0, 0x20, 0, 0x98}, response: iso7816.Response{Status: 0x6300}},
	)

	if err := d.CheckVCI(t.Context()); err != nil {
		t.Fatal(err)
	}

	if err := d.ResetSecurityStatus(t.Context(), protocol.PairingCode); err != nil {
		t.Fatal(err)
	}

	err := d.CheckVCI(t.Context())

	var apduError *iso7816.APDUError
	if !errors.As(err, &apduError) || apduError.StatusWord() != 0x6300 {
		t.Fatalf("CheckVCI after clearing pairing = %v, want APDU status 6300", err)
	}
}

func TestPairingAndVCIInvalidationCloseSession(t *testing.T) {
	for _, operation := range []string{"pairing", "discovery", "pairing status"} {
		t.Run(operation, func(t *testing.T) {
			cause := errors.New("protected response authentication failed")
			step := exchangeStep{err: &transport.DeviceInvalidatedError{Err: cause}}

			var steps []exchangeStep

			switch operation {
			case "pairing":
				step.command = []byte{0, 0x20, 0, 0x98, 8, '1', '2', '3', '4', '5', '6', '7', '8'}
			case "discovery":
				step.command = vciDiscovery(0).command
			case "pairing status":
				steps = append(steps, vciDiscovery(protocol.PINUsageVCI))
				step.command = []byte{0, 0x20, 0, 0x98}
			}

			steps = append(steps, step)
			d, raw := newSMDevice(t, steps...)

			var err error
			if operation == "pairing" {
				err = d.VerifyPairingCode(t.Context(), "12345678")
			} else {
				err = d.CheckVCI(t.Context())
			}

			if !errors.Is(err, cause) || raw.closeCalls != 1 {
				t.Fatalf("operation = %v, close count = %d; want invalidation and one close", err, raw.closeCalls)
			}

			if err := d.CheckVCI(t.Context()); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("CheckVCI after invalidation = %v, want closed pipe", err)
			}
		})
	}
}
