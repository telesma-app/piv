package card

import (
	"context"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
)

// ExchangeAdministration authenticates the card administrator and sends one raw
// command under the same operation gate. Like Exchange, it returns the final
// status word without interpretation. Commands must leave PIV selected.
//
// The optional authentication source runs before the gate. After administration
// authentication, its VERIFY request and the command run under the gate. A nil
// source sends no VERIFY. On a successful source return, the operation owns its
// Data and clears it before returning, including when waiting is canceled. Source
// errors leave ownership with the source. AdministrationKey and command data are
// borrowed for the call and are not retained or cleared.
//
// This operation does not retry. An interrupted command may have completed.
func (d *Device) ExchangeAdministration(
	ctx context.Context,
	command iso7816.Command,
	administrationKey AdministrationKey,
	authentication AuthenticationSource,
) (iso7816.Response, error) {
	if err := ctx.Err(); err != nil {
		return iso7816.Response{}, err
	}

	block, err := administrationKey.block()
	if err != nil {
		return iso7816.Response{}, err
	}

	var request protocol.VerifyRequest

	if authentication != nil {
		request, err = authentication(ctx)
		if err != nil {
			return iso7816.Response{}, err
		}
		defer clear(request.Data)
	}

	if err := d.lock(ctx); err != nil {
		return iso7816.Response{}, err
	}
	defer d.unlock()

	if err := d.authenticateAdministration(ctx, administrationKey.Algorithm, block); err != nil {
		return iso7816.Response{}, d.operationError(err)
	}

	if authentication != nil {
		if err := d.client.Verify(ctx, request); err != nil {
			return iso7816.Response{}, d.operationError(err)
		}
	}

	response, err := d.transport.Exchange(ctx, command)

	return response, d.operationError(err)
}
