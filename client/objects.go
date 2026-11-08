package client

import (
	"context"
	"fmt"

	"github.com/telesma-app/piv/protocol"
)

// GetCHUID reads the Card Holder Unique Identifier without verifying its issuer
// signature or evaluating expiration. An absent object remains an APDU error.
func (c *Client) GetCHUID(ctx context.Context) (protocol.CHUID, error) {
	data, err := c.GetData(ctx, protocol.CardholderUniqueIdentifier)
	if err != nil {
		return protocol.CHUID{}, err
	}

	return protocol.ParseCHUID(data)
}

// GetCCC reads the Card Capability Container without authenticating its contents.
// It describes GSC-IS compatibility, not supported cryptographic algorithms.
func (c *Client) GetCCC(ctx context.Context) (protocol.CCC, error) {
	data, err := c.GetData(ctx, protocol.CardCapabilityContainer)
	if err != nil {
		return protocol.CCC{}, err
	}

	return protocol.ParseCCC(data)
}

// GetPrintedInformation reads the optional Printed Information object without
// authenticating its contents. An absent object remains an APDU error.
func (c *Client) GetPrintedInformation(ctx context.Context) (protocol.PrintedInfo, error) {
	data, err := c.GetData(ctx, protocol.PrintedInformation)
	if err != nil {
		return protocol.PrintedInfo{}, err
	}

	return protocol.ParsePrintedInformation(data)
}

// GetSecurityObject reads the signed hashes and data-group mapping without
// verifying the CMS signature or the integrity of the referenced objects.
func (c *Client) GetSecurityObject(ctx context.Context) (protocol.SecurityObjectData, error) {
	data, err := c.GetData(ctx, protocol.SecurityObject)
	if err != nil {
		return protocol.SecurityObjectData{}, err
	}

	return protocol.ParseSecurityObject(data)
}

// GetPairingCode reads the card's stored pairing code. The card requires PIN
// or OCC verification and a contact connection or VCI; this call does not VERIFY.
func (c *Client) GetPairingCode(ctx context.Context) (string, error) {
	data, err := c.GetData(ctx, protocol.PairingCodeReferenceDataContainer)
	if err != nil {
		return "", err
	}

	return protocol.ParsePairingCode(data)
}

// GetSecureMessagingCertificateSigner reads the content-signing certificate
// and optional intermediate CVC without establishing trust in either.
func (c *Client) GetSecureMessagingCertificateSigner(ctx context.Context) (protocol.SecureMessagingCertificateSigner, error) {
	data, err := c.GetData(ctx, protocol.SecureMessagingCertificateSignerObject)
	if err != nil {
		return protocol.SecureMessagingCertificateSigner{}, err
	}

	return protocol.ParseSecureMessagingCertificateSigner(data)
}

// GetFingerprints reads the cardholder's off-card fingerprint comparison data.
// The card requires PIN or OCC verification; this call does not VERIFY or
// authenticate the biometric signature.
func (c *Client) GetFingerprints(ctx context.Context) (protocol.BiometricData, error) {
	return c.getBiometricData(ctx, protocol.CardholderFingerprints, protocol.BiometricFingerprint)
}

// GetFacialImage reads the cardholder's facial biometric data without
// authenticating its signature or decoding the image.
func (c *Client) GetFacialImage(ctx context.Context) (protocol.BiometricData, error) {
	return c.getBiometricData(ctx, protocol.CardholderFacialImage, protocol.BiometricFace)
}

// GetIrisImages reads the cardholder's iris biometric data. The card requires
// PIN or OCC verification; this call does not VERIFY, authenticate the signature,
// or decode images.
func (c *Client) GetIrisImages(ctx context.Context) (protocol.BiometricData, error) {
	return c.getBiometricData(ctx, protocol.CardholderIrisImages, protocol.BiometricIris)
}

func (c *Client) getBiometricData(ctx context.Context, object protocol.Object, kind protocol.BiometricType) (protocol.BiometricData, error) {
	data, err := c.GetData(ctx, object)
	if err != nil {
		return protocol.BiometricData{}, err
	}

	biometric, err := protocol.ParseBiometricData(data)
	if err != nil {
		return protocol.BiometricData{}, err
	}

	if biometric.Header.BiometricType != kind {
		return protocol.BiometricData{}, fmt.Errorf("%w: biometric type does not match object %x", protocol.ErrInvalidResponse, uint32(object))
	}

	return biometric, nil
}

// GetBiometricInformation reads the BIT Group Template that describes the
// card's on-card fingerprint comparison configuration.
func (c *Client) GetBiometricInformation(ctx context.Context) (protocol.BiometricInformation, error) {
	data, err := c.GetData(ctx, protocol.BiometricInformationTemplates)
	if err != nil {
		return protocol.BiometricInformation{}, err
	}

	return protocol.ParseBiometricInformation(data)
}
