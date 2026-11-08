package client

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
)

// SP 800-73-5 Part 2, Section 3: card commands in specification order.

// 3.1.1. SELECT.

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

// 3.1.2. GET DATA.

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

// 3.2.1. VERIFY.

// ReferenceDataError reports a reference-data check returning an explicit 63Cx
// retry count. It preserves the APDU status for errors.As and never includes secrets.
type ReferenceDataError struct {
	Reference protocol.KeyReference
	Retries   int
	Status    iso7816.StatusWord
}

func (e *ReferenceDataError) Error() string {
	return fmt.Sprintf("piv: reference %02x verification failed (%d retries, SW=%s)", byte(e.Reference), e.Retries, e.Status)
}

func (e *ReferenceDataError) Unwrap() error {
	return &iso7816.APDUError{SW1: e.Status.SW1(), SW2: e.Status.SW2()}
}

// Verify sends the supplied VERIFY operation, including empty status queries,
// security-status resets, and encoded PIN, pairing-code, or OCC data. Data is
// borrowed unchanged; its encoding belongs to the caller. An incorrect value
// can consume a retry.
func (c *Client) Verify(ctx context.Context, request protocol.VerifyRequest) error {
	var p1 byte
	if request.ResetSecurityStatus {
		p1 = 0xff
	}

	return c.referenceCommand(ctx, protocol.Verify, p1, request.Reference, request.Data)
}

// 3.2.2. CHANGE REFERENCE DATA.

// ChangeReferenceData replaces a PIN or PUK using eight-byte encoded values.
// Reference is ApplicationPIN, GlobalPIN, or PUK (SP 800-73-5 Part 2,
// Sec. 3.2.2). An incorrect current value consumes a retry.
func (c *Client) ChangeReferenceData(ctx context.Context, reference protocol.KeyReference, current, replacement [8]byte) error {
	defer clear(current[:])
	defer clear(replacement[:])

	var data [16]byte
	copy(data[:8], current[:])

	copy(data[8:], replacement[:])
	defer clear(data[:])

	return c.referenceCommand(ctx, protocol.ChangeReferenceData, 0, reference, data[:])
}

// 3.2.3. RESET RETRY COUNTER.

// ResetRetryCounter resets the application PIN's retry counter and replaces
// its encoded value. PUK and replacement contain exactly eight encoded bytes;
// card-specific padding belongs to the caller. An incorrect PUK consumes a PUK
// retry.
func (c *Client) ResetRetryCounter(ctx context.Context, puk, replacement [8]byte) error {
	defer clear(puk[:])
	defer clear(replacement[:])

	var data [16]byte
	copy(data[:8], puk[:])

	copy(data[8:], replacement[:])
	defer clear(data[:])

	return c.referenceCommand(ctx, protocol.ResetRetryCounter, 0, protocol.ApplicationPIN, data[:])
}

// 3.2.4. GENERAL AUTHENTICATE.

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

// 3.3.1. PUT DATA.

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

// 3.3.2. GENERATE ASYMMETRIC KEY PAIR.

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
	case protocol.RSA1024, protocol.RSA2048, protocol.RSA3072, protocol.RSA4096,
		protocol.ECCP256, protocol.ECCP384, protocol.ECCP521, protocol.Ed25519, protocol.X25519:
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

func (c *Client) referenceCommand(ctx context.Context, instruction protocol.Instruction, p1 byte, reference protocol.KeyReference, data []byte) error {
	response, err := c.transport.Exchange(ctx, iso7816.Command{
		INS: byte(instruction), P1: p1, P2: byte(reference), Data: data, Encoding: iso7816.EncodingShort,
	})
	if err != nil {
		return err
	}

	if retries, ok := retryStatus(response.Status); ok {
		if len(response.Data) != 0 {
			return protocol.ErrInvalidResponse
		}

		if instruction == protocol.ResetRetryCounter {
			reference = protocol.PUK
		}

		return &ReferenceDataError{Reference: reference, Retries: retries, Status: response.Status}
	}

	if err := response.APDUError(); err != nil {
		return err
	}

	if len(response.Data) != 0 {
		return protocol.ErrInvalidResponse
	}

	return nil
}

func retryStatus(status iso7816.StatusWord) (int, bool) {
	if status&0xfff0 == 0x63c0 {
		return int(status & 0x0f), true
	}

	return 0, false
}
