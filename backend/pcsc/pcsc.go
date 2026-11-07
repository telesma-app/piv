// Package pcsc opens PC/SC cards as PIV transports.
package pcsc

import (
	"context"
	"errors"
	"iter"

	nativepcsc "github.com/telesma-app/pcsc"
	"github.com/telesma-app/piv/transport"
	"github.com/telesma-app/piv/transport/iso7816"
)

// Devices returns PC/SC readers that currently contain a card. It does not open
// the cards or determine whether they support PIV.
func Devices(ctx context.Context) iter.Seq2[*nativepcsc.ReaderInfo, error] {
	return func(yield func(*nativepcsc.ReaderInfo, error) bool) {
		if err := ctx.Err(); err != nil {
			yield(nil, err)
			return
		}

		for reader, err := range nativepcsc.Enumerate() {
			if err := ctx.Err(); err != nil {
				yield(nil, err)
				return
			}

			if err != nil {
				yield(nil, err)
				return
			}

			if reader.State&nativepcsc.ReaderStatePresent == 0 {
				continue
			}

			if !yield(reader, nil) {
				return
			}
		}
	}
}

// Open opens an exclusive card connection and selects PIV. The returned
// transport owns the card, retains the initial ApplicationProperties and resets
// the card on Close.
func Open(ctx context.Context, reader string) (*iso7816.Transport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	card, err := nativepcsc.Open(
		reader,
		nativepcsc.WithShareMode(nativepcsc.ShareModeExclusive),
		nativepcsc.WithDisconnectDisposition(nativepcsc.DispositionResetCard),
	)
	if err != nil {
		return nil, err
	}

	device, err := iso7816.Open(ctx, card)
	if err != nil {
		return nil, errors.Join(err, card.Close())
	}

	return device, nil
}

// Enumerate opens inserted PC/SC cards as PIV transports and transfers ownership
// of every successful result to the consumer. Failed candidates are closed.
func Enumerate(ctx context.Context) iter.Seq2[transport.Device, error] {
	return func(yield func(transport.Device, error) bool) {
		for reader, err := range Devices(ctx) {
			if err != nil {
				yield(nil, err)
				return
			}

			device, err := Open(ctx, reader.Name)
			if err != nil {
				if !yield(nil, err) {
					return
				}

				continue
			}

			if !yield(device, nil) {
				return
			}
		}
	}
}
