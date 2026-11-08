package client

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

// Client sends PIV commands through a borrowed transport.
type Client struct {
	transport transport.APDU
}

// NewClient borrows a transport without performing I/O. Select PIV before
// sending commands; backend/pcsc.Open and transport/iso7816.Open do this already.
func NewClient(transport transport.APDU) *Client {
	return &Client{transport: transport}
}

func (c *Client) exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	response, err := c.transport.Exchange(ctx, command)
	if err != nil {
		return iso7816.Response{}, err
	}

	if err := response.APDUError(); err != nil {
		return iso7816.Response{}, err
	}

	return response, nil
}

// Select activates PIV and parses its application property template. Selecting
// PIV again preserves its security status; switching to another application
// clears PIV's application-specific security status (SP 800-73-5 Part 2,
// Sec. 3.1.1).
func (c *Client) Select(ctx context.Context) (protocol.ApplicationPropertyTemplate, error) {
	response, err := c.exchange(ctx, protocol.SelectCommand())
	if err != nil {
		return protocol.ApplicationPropertyTemplate{}, fmt.Errorf("piv: SELECT: %w", err)
	}

	return protocol.ParseApplicationPropertyTemplate(response.Data)
}

func objectTag(object protocol.Object) []byte {
	switch {
	case object <= 0xff:
		return []byte{byte(object)}
	case object <= 0xffff:
		return []byte{byte(object >> 8), byte(object)}
	case object <= 0xffffff:
		return []byte{byte(object >> 16), byte(object >> 8), byte(object)}
	default:
		return []byte{byte(object >> 24), byte(object >> 16), byte(object >> 8), byte(object)}
	}
}

func objectTemplate(object protocol.Object) uint32 {
	switch object {
	case protocol.DiscoveryObject, protocol.BiometricInformationTemplates:
		return uint32(object)
	default:
		return 0x53
	}
}

// GetData reads an object and returns its contents without the outer 53, 7E,
// or 7F61 template. An absent object is reported as an iso7816.APDUError (6A82).
func (c *Client) GetData(ctx context.Context, object protocol.Object) ([]byte, error) {
	response, err := c.exchange(ctx, iso7816.Command{
		INS: byte(protocol.GetData), P1: 0x3f, P2: 0xff,
		Data: bertlv.Append(nil, 0x5c, objectTag(object)),
		Le:   256, Encoding: iso7816.EncodingShort,
	})
	if err != nil {
		return nil, fmt.Errorf("piv: GET DATA %x: %w", uint32(object), err)
	}

	return protocol.ParseObject(response.Data, objectTemplate(object))
}

// PutData replaces an object's contents. It requires prior administration
// authentication.
func (c *Client) PutData(ctx context.Context, object protocol.Object, data []byte) error {
	// Discovery and BIT use their own templates without a tag-list selector
	// (SP 800-73-5 Part 2, Tables 8-10).
	var request []byte
	if object != protocol.DiscoveryObject && object != protocol.BiometricInformationTemplates {
		request = bertlv.Append(request, 0x5c, objectTag(object))
	}

	request = bertlv.Append(request, objectTemplate(object), data)

	response, err := c.exchange(ctx, iso7816.Command{
		INS: byte(protocol.PutData), P1: 0x3f, P2: 0xff,
		Data: request, Encoding: iso7816.EncodingShort,
	})
	if err != nil {
		return fmt.Errorf("piv: PUT DATA %x: %w", uint32(object), err)
	}

	if len(response.Data) != 0 {
		return protocol.ErrInvalidResponse
	}

	return nil
}

// PutCertificate replaces a slot's certificate using caller-encoded DER.
// It requires prior administration authentication. It neither parses the DER
// nor verifies certificate trust or a match with the slot's private key. The
// key itself is not changed.
func (c *Client) PutCertificate(ctx context.Context, key protocol.KeyReference, der []byte) error {
	object, err := protocol.CertificateObject(key)
	if err != nil {
		return err
	}

	return c.PutData(ctx, object, protocol.EncodeCertificate(der))
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
	object, err := protocol.CertificateObject(key)
	if err != nil {
		return nil, err
	}

	data, err := c.GetData(ctx, object)
	if err != nil {
		return nil, err
	}

	return protocol.DecodeCertificate(data)
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

// GeneralAuthenticate exchanges a dynamic authentication template. It supports
// raw private-key operations and multi-step administration authentication. The
// caller performs any required hashing, padding, challenge verification, or KDF.
// Response bytes are cleared if the authentication template cannot be parsed.
func (c *Client) GeneralAuthenticate(
	ctx context.Context,
	algorithm protocol.Algorithm,
	key protocol.KeyReference,
	data protocol.DynamicAuthentication,
) (protocol.DynamicAuthentication, error) {
	request, err := data.MarshalBinary()
	if err != nil {
		return protocol.DynamicAuthentication{}, err
	}
	defer clear(request)

	response, err := c.exchange(ctx, iso7816.Command{
		INS: byte(protocol.GeneralAuthenticate), P1: byte(algorithm), P2: byte(key),
		Data: request, Le: 256, Encoding: iso7816.EncodingShort,
	})
	if err != nil {
		return protocol.DynamicAuthentication{}, fmt.Errorf("piv: GENERAL AUTHENTICATE: %w", err)
	}
	// A successful single-authentication completion has no response template.
	if len(response.Data) == 0 {
		return protocol.DynamicAuthentication{}, nil
	}

	authentication, err := protocol.ParseDynamicAuthentication(response.Data)
	if err != nil {
		// A malformed template can still contain decrypted key material.
		clear(response.Data)
		return protocol.DynamicAuthentication{}, err
	}

	return authentication, nil
}

// KeyGenerationError reports an acknowledged key replacement whose returned
// public key is invalid or does not match the request. The key was generated;
// retrying would replace it again. Transport failures before acknowledgement
// do not use this type because their effect may be unknown.
type KeyGenerationError struct {
	Key       protocol.KeyReference
	Algorithm protocol.Algorithm
	Err       error
}

func (e *KeyGenerationError) Error() string {
	return fmt.Sprintf("piv: key %02x generated with algorithm %02x, but public key response is invalid: %v", byte(e.Key), byte(e.Algorithm), e.Err)
}

func (e *KeyGenerationError) Unwrap() error {
	return e.Err
}

// GenerateAsymmetricKeyPair replaces a slot's private key and returns the
// generated public key. It requires prior administration authentication.
// Existing certificates are not updated. This operation is irreversible. A
// KeyGenerationError means the card acknowledged replacement but returned an
// invalid public key or a different RSA exponent than requested.
func (c *Client) GenerateAsymmetricKeyPair(
	ctx context.Context,
	request protocol.GenerateAsymmetricKeyPairRequest,
) (crypto.PublicKey, error) {
	switch request.Algorithm {
	case protocol.RSA1024, protocol.RSA2048, protocol.RSA3072, protocol.ECCP256, protocol.ECCP384:
	default:
		return nil, fmt.Errorf("piv: unsupported public key algorithm %02x", byte(request.Algorithm))
	}

	template := bertlv.Append(nil, 0x80, []byte{byte(request.Algorithm)})
	if request.Parameter != nil {
		template = bertlv.Append(template, 0x81, request.Parameter)
	}

	response, err := c.exchange(ctx, iso7816.Command{
		INS: byte(protocol.GenerateAsymmetricKeyPair), P2: byte(request.Key),
		Data: bertlv.Append(nil, 0xac, template),
		Le:   256, Encoding: iso7816.EncodingShort,
	})
	if err != nil {
		return nil, fmt.Errorf("piv: GENERATE ASYMMETRIC KEY PAIR: %w", err)
	}

	publicKey, err := protocol.ParsePublicKey(request.Algorithm, response.Data)
	if err != nil {
		return nil, &KeyGenerationError{Key: request.Key, Algorithm: request.Algorithm, Err: err}
	}

	if key, ok := publicKey.(*rsa.PublicKey); ok && request.Parameter != nil {
		if new(big.Int).SetBytes(request.Parameter).Cmp(big.NewInt(int64(key.E))) != 0 {
			return nil, &KeyGenerationError{
				Key: request.Key, Algorithm: request.Algorithm,
				Err: fmt.Errorf("%w: generated RSA public exponent does not match request", protocol.ErrInvalidResponse),
			}
		}
	}

	return publicKey, nil
}
