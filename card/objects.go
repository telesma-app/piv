package card

import (
	"context"

	"github.com/telesma-app/piv/protocol"
)

// GetCHUID reads the Card Holder Unique Identifier without verifying its issuer
// signature or evaluating expiration.
func (d *Device) GetCHUID(ctx context.Context) (protocol.CHUID, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.CHUID{}, err
	}
	defer d.unlock()

	chuid, err := d.client.GetCHUID(ctx)

	return chuid, d.operationError(err)
}

// GetCCC reads the Card Capability Container without authenticating its contents.
// It describes GSC-IS compatibility, not supported cryptographic algorithms.
func (d *Device) GetCCC(ctx context.Context) (protocol.CCC, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.CCC{}, err
	}
	defer d.unlock()

	ccc, err := d.client.GetCCC(ctx)

	return ccc, d.operationError(err)
}

// GetPrintedInformation reads the optional Printed Information object without
// authenticating its contents. Absence is an APDU error.
func (d *Device) GetPrintedInformation(ctx context.Context) (protocol.PrintedInfo, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.PrintedInfo{}, err
	}
	defer d.unlock()

	info, err := d.client.GetPrintedInformation(ctx)

	return info, d.operationError(err)
}

// GetSecurityObject reads the signed hashes and data-group mapping without
// verifying the CMS signature or the integrity of the referenced objects.
func (d *Device) GetSecurityObject(ctx context.Context) (protocol.SecurityObjectData, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.SecurityObjectData{}, err
	}
	defer d.unlock()

	object, err := d.client.GetSecurityObject(ctx)

	return object, d.operationError(err)
}

// GetPairingCode reads the stored pairing code under the current PIN or OCC
// security status. It requires a contact connection or VCI and does not VERIFY.
func (d *Device) GetPairingCode(ctx context.Context) (string, error) {
	if err := d.lock(ctx); err != nil {
		return "", err
	}
	defer d.unlock()

	code, err := d.client.GetPairingCode(ctx)

	return code, d.operationError(err)
}

// GetSecureMessagingCertificateSigner reads the content-signing certificate
// and optional intermediate CVC without establishing trust in either.
func (d *Device) GetSecureMessagingCertificateSigner(ctx context.Context) (protocol.SecureMessagingCertificateSigner, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.SecureMessagingCertificateSigner{}, err
	}
	defer d.unlock()

	signer, err := d.client.GetSecureMessagingCertificateSigner(ctx)

	return signer, d.operationError(err)
}

// GetFingerprints reads off-card fingerprint comparison data under the current
// PIN or OCC security status without verifying the biometric signature.
func (d *Device) GetFingerprints(ctx context.Context) (protocol.BiometricData, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.BiometricData{}, err
	}
	defer d.unlock()

	biometric, err := d.client.GetFingerprints(ctx)

	return biometric, d.operationError(err)
}

// GetFacialImage reads the cardholder's facial biometric data without
// authenticating its signature or decoding the image.
func (d *Device) GetFacialImage(ctx context.Context) (protocol.BiometricData, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.BiometricData{}, err
	}
	defer d.unlock()

	biometric, err := d.client.GetFacialImage(ctx)

	return biometric, d.operationError(err)
}

// GetIrisImages reads iris biometric data under the current PIN or OCC security
// status without authenticating the signature or decoding images.
func (d *Device) GetIrisImages(ctx context.Context) (protocol.BiometricData, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.BiometricData{}, err
	}
	defer d.unlock()

	biometric, err := d.client.GetIrisImages(ctx)

	return biometric, d.operationError(err)
}

// GetBiometricInformation reads the BIT Group Template that describes the
// card's on-card fingerprint comparison configuration.
func (d *Device) GetBiometricInformation(ctx context.Context) (protocol.BiometricInformation, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.BiometricInformation{}, err
	}
	defer d.unlock()

	information, err := d.client.GetBiometricInformation(ctx)

	return information, d.operationError(err)
}
