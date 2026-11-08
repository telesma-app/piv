package client

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/telesma-app/piv/protocol"
)

// Typed GET DATA operations follow SP 800-73-5 Part 1, Section 3.

// GetCCC reads the Card Capability Container without authenticating its contents.
// It describes GSC-IS compatibility, not supported cryptographic algorithms.
func (c *Client) GetCCC(ctx context.Context) (protocol.CCC, error) {
	data, err := c.GetData(ctx, protocol.CardCapabilityContainer)
	if err != nil {
		return protocol.CCC{}, err
	}

	return protocol.ParseCCC(data)
}

// GetCHUID reads the Card Holder Unique Identifier without verifying its issuer
// signature or evaluating expiration. An absent object remains an APDU error.
func (c *Client) GetCHUID(ctx context.Context) (protocol.CHUID, error) {
	data, err := c.GetData(ctx, protocol.CardholderUniqueIdentifier)
	if err != nil {
		return protocol.CHUID{}, err
	}

	return protocol.ParseCHUID(data)
}

// GetCertificate reads and parses the X.509 certificate in a key slot.
// Parsing does not verify the certificate or establish trust in its issuer.
func (c *Client) GetCertificate(ctx context.Context, key protocol.KeyReference) (*x509.Certificate, error) {
	object, err := protocol.CertificateObject(key)
	if err != nil {
		return nil, err
	}

	data, err := c.GetData(ctx, object)
	if err != nil {
		return nil, err
	}

	return protocol.ParseCertificate(data)
}

// GetCertificateDER reads a slot's certificate bytes, decompressing GZIP data
// when needed. It does not parse or validate the X.509 certificate, so bytes
// remain available even when GetCertificate cannot parse them.
func (c *Client) GetCertificateDER(ctx context.Context, key protocol.KeyReference) ([]byte, error) {
	certificate, err := c.GetCertificateData(ctx, key)
	return certificate.DER, err
}

// GetCertificateData reads a slot's certificate object, decompressing its DER
// and preserving any legacy MSCUID from a retired key-management certificate.
// It does not parse X.509 contents or establish trust.
func (c *Client) GetCertificateData(ctx context.Context, key protocol.KeyReference) (protocol.CertificateData, error) {
	object, err := protocol.CertificateObject(key)
	if err != nil {
		return protocol.CertificateData{}, err
	}

	data, err := c.GetData(ctx, object)
	if err != nil {
		return protocol.CertificateData{}, err
	}

	return protocol.ParseCertificateData(data)
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

// GetSecurityObject reads the signed hashes and data-group mapping without
// verifying the CMS signature or the integrity of the referenced objects.
func (c *Client) GetSecurityObject(ctx context.Context) (protocol.SecurityObjectData, error) {
	data, err := c.GetData(ctx, protocol.SecurityObject)
	if err != nil {
		return protocol.SecurityObjectData{}, err
	}

	return protocol.ParseSecurityObject(data)
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

// GetDiscovery reads the optional Discovery Object, including its PIN Usage
// Policy. An absent object remains an iso7816.APDUError (6A82). The policy is
// returned as metadata; it does not select a PIN or establish a VCI.
func (c *Client) GetDiscovery(ctx context.Context) (protocol.Discovery, error) {
	data, err := c.GetData(ctx, protocol.DiscoveryObject)
	if err != nil {
		return protocol.Discovery{}, err
	}

	return protocol.ParseDiscovery(data)
}

// GetKeyHistory reads the retired key management metadata. An absent object is
// reported as an iso7816.APDUError (6A82). Off-card certificates are not fetched.
func (c *Client) GetKeyHistory(ctx context.Context) (protocol.KeyHistory, error) {
	data, err := c.GetData(ctx, protocol.KeyHistoryObject)
	if err != nil {
		return protocol.KeyHistory{}, err
	}

	return protocol.ParseKeyHistory(data)
}

// GetIrisImages reads the cardholder's iris biometric data. The card requires
// PIN or OCC verification; this call does not VERIFY, authenticate the signature,
// or decode images.
func (c *Client) GetIrisImages(ctx context.Context) (protocol.BiometricData, error) {
	return c.getBiometricData(ctx, protocol.CardholderIrisImages, protocol.BiometricIris)
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

// GetSecureMessagingCertificateSigner reads the content-signing certificate
// and optional intermediate CVC without establishing trust in either.
func (c *Client) GetSecureMessagingCertificateSigner(ctx context.Context) (protocol.SecureMessagingCertificateSigner, error) {
	data, err := c.GetData(ctx, protocol.SecureMessagingCertificateSignerObject)
	if err != nil {
		return protocol.SecureMessagingCertificateSigner{}, err
	}

	return protocol.ParseSecureMessagingCertificateSigner(data)
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
