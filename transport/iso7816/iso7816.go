// Package iso7816 exchanges PIV commands over ISO 7816 card connections.
package iso7816

import (
	"context"
	"errors"
	"fmt"

	baseiso7816 "github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	pivtransport "github.com/telesma-app/piv/transport"
)

const maxShortCommandAPDULength = 261

// Select activates the PIV application and parses its application property
// template. Call it before Exchange and after switching applets. It borrows card
// and never closes it, including on transport or template parsing failure.
func Select(ctx context.Context, card baseiso7816.Card) (protocol.ApplicationPropertyTemplate, error) {
	response, err := Exchange(ctx, card, protocol.SelectCommand())
	if err != nil {
		return protocol.ApplicationPropertyTemplate{}, fmt.Errorf("iso7816: select PIV application: %w", err)
	}

	if err := response.APDUError(); err != nil {
		return protocol.ApplicationPropertyTemplate{}, fmt.Errorf("iso7816: select PIV application: %w", err)
	}

	return protocol.ParseApplicationPropertyTemplate(response.Data)
}

// Exchange borrows a selected PIV card for one command. It uses short APDUs
// with 255-byte command fragments unless EncodingExtended is explicitly set,
// and collects GET RESPONSE data. Framing GET RESPONSE commands use CLA 00.
// A rejected intermediate fragment returns an APDUError; the final status word
// is not interpreted. Callers must serialize whole exchanges and close card
// after DeviceInvalidatedError. Cancellation before
// the first APDU preserves the card; interruption after I/O invalidates it.
func Exchange(ctx context.Context, rawCard baseiso7816.Card, command baseiso7816.Command) (baseiso7816.Response, error) {
	if err := ctx.Err(); err != nil {
		return baseiso7816.Response{}, err
	}

	commands := []baseiso7816.Command{command}
	if command.Encoding != baseiso7816.EncodingExtended {
		command.Encoding = baseiso7816.EncodingShort

		var err error

		commands, err = baseiso7816.Chain(command, maxShortCommandAPDULength)
		if err != nil {
			return baseiso7816.Response{}, err
		}
	}

	card := &ioCard{Card: rawCard}

	response, err := baseiso7816.ExchangeChain(ctx, card, commands, baseiso7816.WithGetResponseCLA(0))
	if err != nil {
		return baseiso7816.Response{}, card.exchangeError(err)
	}

	return response, nil
}

type ioCard struct {
	baseiso7816.Card
	started bool
}

func (c *ioCard) Transmit(ctx context.Context, apdu []byte) ([]byte, error) {
	c.started = true

	response, err := c.Card.Transmit(ctx, apdu)
	if err != nil {
		return response, &pivtransport.IOError{Operation: pivtransport.IOTransmit, Err: err}
	}

	return response, nil
}

func (c *ioCard) exchangeError(err error) error {
	var apduError *baseiso7816.APDUError
	if errors.As(err, &apduError) {
		if _, moreData := apduError.StatusWord().MoreDataLength(); !moreData {
			return err
		}
		// An intermediate fragment must acknowledge receipt, not start a
		// response while the command chain is incomplete.
		err = baseiso7816.ErrInvalidResponse
	}

	if c.started {
		return &pivtransport.DeviceInvalidatedError{Err: err}
	}

	return err
}
