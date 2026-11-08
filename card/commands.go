package card

import (
	"context"
	"crypto"
	"fmt"

	"github.com/telesma-app/piv/protocol"
)

// SP 800-73-5 Part 2, Section 3: card commands in specification order.

// 3.1.2. GET DATA.

// GetData reads a PIV object without its outer template. An absent object is
// reported as an iso7816.APDUError with status 6A82.
func (d *Device) GetData(ctx context.Context, object protocol.Object) ([]byte, error) {
	if err := d.lock(ctx); err != nil {
		return nil, err
	}
	defer d.unlock()

	data, err := d.client.GetData(ctx, object)

	return data, d.operationError(err)
}

// 3.2.1. VERIFY.

// Verify sends an encoded VERIFY operation under the card's operation gate.
// This includes empty status queries, security-status resets, and PIN,
// pairing-code, or OCC authentication data. Request data is borrowed unchanged.
// An incorrect value can consume a retry.
// Separate calls do not form an atomic authentication workflow.
func (d *Device) Verify(ctx context.Context, request protocol.VerifyRequest) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.Verify(ctx, request))
}

// 3.2.2. CHANGE REFERENCE DATA.

// ChangeReferenceData replaces a PIN or PUK using eight-byte encoded values.
// Reference is ApplicationPIN, GlobalPIN, or PUK (SP 800-73-5 Part 2,
// Sec. 3.2.2). An incorrect current value consumes a retry. Card-specific
// padding belongs to the caller.
func (d *Device) ChangeReferenceData(ctx context.Context, reference protocol.KeyReference, current, replacement [8]byte) error {
	defer clear(current[:])
	defer clear(replacement[:])

	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.ChangeReferenceData(ctx, reference, current, replacement))
}

// 3.2.3. RESET RETRY COUNTER.

// ResetRetryCounter resets the application PIN's retry counter and replaces
// its value using an eight-byte PUK and eight-byte encoded replacement. Padding
// belongs to the caller. An incorrect PUK consumes a retry.
func (d *Device) ResetRetryCounter(ctx context.Context, puk, replacement [8]byte) error {
	defer clear(puk[:])
	defer clear(replacement[:])

	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.ResetRetryCounter(ctx, puk, replacement))
}

// 3.3.1. PUT DATA.

// PutData authenticates the card administrator and replaces a PIV object's
// contents under one operation gate. Data is the object value without its outer
// template, as returned by GetData. It is borrowed for the call. An interrupted
// write may have completed; the library does not read it back implicitly.
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
// write may have completed; the library does not read it back implicitly.
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

// 3.3.2. GENERATE ASYMMETRIC KEY PAIR.

// GenerateAsymmetricKeyPair authenticates the card administrator and replaces
// a slot's private key under one operation gate. It returns the generated public
// key; the old certificate is not changed.
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
	case protocol.RSA1024, protocol.RSA2048, protocol.RSA3072, protocol.RSA4096,
		protocol.ECCP256, protocol.ECCP384, protocol.ECCP521, protocol.Ed25519, protocol.X25519:
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
