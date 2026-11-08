package card

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

// Administrator authentication: SP 800-73-5 Part 2, Appendix A.2.

// ErrAdministrationAuthentication means the card's proof did not match the client
// challenge. The session is invalidated because administration authorization may
// already have been granted by the card.
var ErrAdministrationAuthentication = errors.New("piv: administration authentication failed")

// AdministrationKey supplies the administration key and its explicit algorithm.
// Key is borrowed for the duration of an operation and must not be modified
// concurrently. Device neither retains nor clears it. The caller selects
// TripleDESLegacy, TripleDES, AES128, AES192, or AES256. Both Triple DES
// identifiers use 24-byte keys; the requested identifier is sent unchanged.
type AdministrationKey struct {
	Algorithm protocol.Algorithm
	Key       []byte
}

// ExchangeAdministration authenticates the card administrator and sends one raw
// command under the same operation gate. Like Exchange, it returns the final
// status word without interpretation. Commands must leave PIV selected.
//
// Authentication follows [AuthenticationSource], with administration
// authentication preceding VERIFY under the gate. AdministrationKey and command
// data are borrowed for the call and are not retained or cleared.
//
// An interrupted command may have completed.
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

// authenticateAdministration runs SP 800-73-5 Part 2, Appendix A.2 while the caller
// holds the operation gate. The two GA commands and the administrative command
// must not be interleaved with another operation on this connection.
func (d *Device) authenticateAdministration(ctx context.Context, algorithm protocol.Algorithm, block cipher.Block) error {
	authentication, err := d.client.GeneralAuthenticate(ctx, algorithm, protocol.CardApplicationAdministration, protocol.DynamicAuthentication{
		Witness: []byte{},
	})
	if err != nil {
		return administrationResponseError(err)
	}

	if len(authentication.Witness) != block.BlockSize() || authentication.Challenge != nil ||
		authentication.Response != nil || authentication.Exponentiation != nil {
		return &transport.DeviceInvalidatedError{Err: fmt.Errorf("%w: invalid administration witness", protocol.ErrInvalidResponse)}
	}

	witness := make([]byte, block.BlockSize())
	defer clear(witness)

	block.Decrypt(witness, authentication.Witness)

	challenge := make([]byte, block.BlockSize())
	defer clear(challenge)

	rand.Read(challenge)

	expected := make([]byte, block.BlockSize())
	defer clear(expected)

	block.Encrypt(expected, challenge)

	authentication, err = d.client.GeneralAuthenticate(ctx, algorithm, protocol.CardApplicationAdministration, protocol.DynamicAuthentication{
		Witness: witness, Challenge: challenge, Response: []byte{},
	})
	if err != nil {
		return administrationResponseError(err)
	}

	if len(authentication.Response) != block.BlockSize() || authentication.Witness != nil ||
		authentication.Challenge != nil || authentication.Exponentiation != nil {
		return &transport.DeviceInvalidatedError{Err: fmt.Errorf("%w: invalid administration response", protocol.ErrInvalidResponse)}
	}

	if subtle.ConstantTimeCompare(authentication.Response, expected) != 1 {
		return &transport.DeviceInvalidatedError{Err: ErrAdministrationAuthentication}
	}

	return nil
}

func (key AdministrationKey) block() (cipher.Block, error) {
	var size int

	switch key.Algorithm {
	case protocol.TripleDESLegacy, protocol.TripleDES:
		size = 24
	case protocol.AES128:
		size = 16
	case protocol.AES192:
		size = 24
	case protocol.AES256:
		size = 32
	default:
		return nil, fmt.Errorf("piv: unsupported administration key algorithm %02x", byte(key.Algorithm))
	}

	if len(key.Key) != size {
		return nil, fmt.Errorf("piv: administration key algorithm %02x requires %d bytes", byte(key.Algorithm), size)
	}

	if key.Algorithm == protocol.TripleDESLegacy || key.Algorithm == protocol.TripleDES {
		return des.NewTripleDESCipher(key.Key)
	}

	return aes.NewCipher(key.Key)
}

// A malformed successful authentication response is not an APDU rejection. The
// card may already have authorized administration, so the session cannot be reused.
func administrationResponseError(err error) error {
	if errors.Is(err, protocol.ErrInvalidResponse) {
		return &transport.DeviceInvalidatedError{Err: err}
	}

	return err
}
