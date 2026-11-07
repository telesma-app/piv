package card

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

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

// GenerateAsymmetricKeyPair authenticates the card administrator and replaces
// a slot's private key under one operation gate. It returns the generated public
// key; the old certificate is not changed. It does not retry or write a certificate.
//
// A client.KeyGenerationError means the card acknowledged replacing the key but
// its public key is invalid or does not match the request. An interrupted
// exchange may also have replaced the key without returning its public key.
// Neither outcome is safe to retry automatically.
func (d *Device) GenerateAsymmetricKeyPair(
	ctx context.Context,
	request protocol.GenerateAsymmetricKeyPairRequest,
	administrationKey AdministrationKey,
) (crypto.PublicKey, error) {
	// Reject an algorithm whose generated public key cannot be parsed before
	// starting administration authentication.
	switch request.Algorithm {
	case protocol.RSA1024, protocol.RSA2048, protocol.RSA3072, protocol.ECCP256, protocol.ECCP384:
	default:
		return nil, fmt.Errorf("piv: unsupported public key algorithm %02x", byte(request.Algorithm))
	}

	block, err := administrationKey.block()
	if err != nil {
		return nil, err
	}

	if err := d.lock(ctx); err != nil {
		return nil, err
	}

	defer d.unlock()

	if err := d.authenticateAdministration(ctx, administrationKey.Algorithm, block); err != nil {
		return nil, d.operationError(err)
	}

	publicKey, err := d.client.GenerateAsymmetricKeyPair(ctx, request)

	return publicKey, d.operationError(err)
}

// PutData authenticates the card administrator and replaces a PIV object's
// contents under one operation gate. Data is the object value without its outer
// template, as returned by GetData. It is borrowed for the call. An interrupted
// write may have completed; the library does not retry it or read it back implicitly.
func (d *Device) PutData(
	ctx context.Context,
	object protocol.Object,
	data []byte,
	administrationKey AdministrationKey,
) error {
	block, err := administrationKey.block()
	if err != nil {
		return err
	}

	if err := d.lock(ctx); err != nil {
		return err
	}

	defer d.unlock()

	if err := d.authenticateAdministration(ctx, administrationKey.Algorithm, block); err != nil {
		return d.operationError(err)
	}

	return d.operationError(d.client.PutData(ctx, object, data))
}

// PutCertificate authenticates the card administrator and replaces a slot's
// certificate under one operation gate. DER is an already encoded certificate;
// it is not parsed, checked for trust, or matched to the slot's private key. Use
// a generated public key to check that match before installation.
//
// This operation is independent of GenerateAsymmetricKeyPair. A failed
// certificate write does not undo an earlier key generation. An interrupted
// write may have completed; the library does not retry it or read it back
// implicitly.
func (d *Device) PutCertificate(
	ctx context.Context,
	key protocol.KeyReference,
	der []byte,
	administrationKey AdministrationKey,
) error {
	object, err := protocol.CertificateObject(key)
	if err != nil {
		return err
	}

	return d.PutData(ctx, object, protocol.EncodeCertificate(der), administrationKey)
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

// A malformed successful authentication response is not an APDU rejection. The
// card may already have authorized administration, so the session cannot be reused.
func administrationResponseError(err error) error {
	if errors.Is(err, protocol.ErrInvalidResponse) {
		return &transport.DeviceInvalidatedError{Err: err}
	}

	return err
}
