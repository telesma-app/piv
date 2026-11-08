package sm

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

// Parameters supplies explicit card trust, cipher suite and protected APDU encoding.
// HostID is a locally assigned client identifier; zero is permitted by NIST.
// CipherSuite must be protocol.CipherSuite2 or protocol.CipherSuite7.
// Encoding must be EncodingShort (with chaining) or EncodingExtended. Handshake
// commands use short encoding. No suite or encoding fallback is performed.
type Parameters struct {
	Trust       Trust
	CipherSuite protocol.Algorithm
	HostID      [8]byte
	Encoding    iso7816.Encoding
}

// Open reselects PIV, requires support for the requested suite, and authenticates
// a fresh session against parameters.Trust. The caller serializes initialization with
// all other connection users. Ownership transfers only on success. On failure
// the caller retains ownership; a DeviceInvalidatedError additionally means the
// connection has been closed and must not be reused.
func Open(ctx context.Context, connection transport.Device, parameters Parameters) (*Transport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if parameters.Encoding != iso7816.EncodingShort && parameters.Encoding != iso7816.EncodingExtended {
		return nil, fmt.Errorf("sm: select short or extended APDU encoding explicitly")
	}

	suite, err := selectCipherSuite(parameters.CipherSuite)
	if err != nil {
		return nil, err
	}

	keys, application, certificate, err := establish(ctx, connection, parameters, suite)
	if err != nil {
		var invalidated *transport.DeviceInvalidatedError
		if errors.As(err, &invalidated) {
			return nil, errors.Join(err, connection.Close())
		}

		return nil, err
	}
	defer keys.clear()

	return &Transport{
		connection:  connection,
		application: application,
		certificate: certificate,
		session:     newRecordSession(keys, parameters.Encoding),
		mu:          make(chan struct{}, 1),
		closed:      make(chan struct{}),
	}, nil
}

// establish follows the client application steps in SP 800-73-5 Part 2, Section 4.1.1.
func establish(ctx context.Context, connection transport.Device, parameters Parameters, suite cipherSuite) (sessionKeys, protocol.ApplicationPropertyTemplate, CardCertificate, error) {
	response, err := connection.Exchange(ctx, protocol.SelectCommand())
	if err != nil {
		return sessionKeys{}, protocol.ApplicationPropertyTemplate{}, CardCertificate{}, err
	}

	if err := response.APDUError(); err != nil {
		return sessionKeys{}, protocol.ApplicationPropertyTemplate{}, CardCertificate{}, fmt.Errorf("sm: SELECT PIV: %w", err)
	}

	application, err := protocol.ParseApplicationPropertyTemplate(response.Data)
	if err != nil {
		return sessionKeys{}, protocol.ApplicationPropertyTemplate{}, CardCertificate{}, err
	}

	// Retain borrowed SELECT fields before the connection reuses response storage.
	application.AID = bytes.Clone(application.AID)
	application.TagAllocationAuthorityAID = bytes.Clone(application.TagAllocationAuthorityAID)

	if !slices.Contains(application.Algorithms, suite.algorithm) {
		return sessionKeys{}, protocol.ApplicationPropertyTemplate{}, CardCertificate{}, fmt.Errorf("sm: selected PIV application does not advertise cipher suite %02X", byte(suite.algorithm))
	}

	ephemeral, err := suite.curve.GenerateKey(rand.Reader)
	if err != nil {
		return sessionKeys{}, protocol.ApplicationPropertyTemplate{}, CardCertificate{}, err
	}

	public := ephemeral.PublicKey().Bytes()

	response, err = connection.Exchange(ctx, establishmentCommand(suite, parameters.HostID, public))
	if err != nil {
		return sessionKeys{}, protocol.ApplicationPropertyTemplate{}, CardCertificate{}, err
	}

	if err := response.APDUError(); err != nil {
		return sessionKeys{}, protocol.ApplicationPropertyTemplate{}, CardCertificate{}, fmt.Errorf("sm: GENERAL AUTHENTICATE: %w", err)
	}

	nonce, cryptogram, certificate, err := parseEstablishmentResponse(suite, response.Data)
	if err != nil {
		return sessionKeys{}, protocol.ApplicationPropertyTemplate{}, CardCertificate{}, invalidHandshake(err)
	}

	peer, err := verifyCertificate(suite, certificate, parameters.Trust)
	if err != nil {
		return sessionKeys{}, protocol.ApplicationPropertyTemplate{}, CardCertificate{}, invalidHandshake(err)
	}

	z, err := ephemeral.ECDH(peer.PublicKey)
	if err != nil {
		return sessionKeys{}, protocol.ApplicationPropertyTemplate{}, CardCertificate{}, invalidHandshake(err)
	}
	defer clear(z)

	// IDsICC hashes the complete encoded CVC, including tag and length (§4.1.3).
	hash := sha256.Sum256(certificate)
	cardID := [8]byte(hash[:8])
	keys := deriveKeys(suite, z, parameters.HostID, cardID, public, nonce)
	confirmation := append([]byte("KC_1_V"), cardID[:]...)
	confirmation = append(confirmation, parameters.HostID[:]...)
	confirmation = append(confirmation, public[1:]...)
	expected := cmac(keys.cfrm[:keys.keySize], confirmation)
	clear(keys.cfrm[:])

	if subtle.ConstantTimeCompare(expected[:], cryptogram) != 1 {
		keys.clear()
		return sessionKeys{}, protocol.ApplicationPropertyTemplate{}, CardCertificate{}, invalidHandshake(ErrAuthentication)
	}

	// The authenticated CVC is retained after later exchanges reuse response storage.
	peer.Raw = bytes.Clone(peer.Raw)

	return keys, application, peer, nil
}

// establishmentCommand encodes the key establishment command from Section 4.1.8.
func establishmentCommand(suite cipherSuite, hostID [8]byte, public []byte) iso7816.Command {
	challenge := append([]byte{0}, hostID[:]...)
	challenge = append(challenge, public...)
	data := bertlv.Append(nil, 0x81, challenge)
	data = bertlv.Append(data, 0x82, nil)

	return iso7816.Command{
		INS: byte(protocol.GeneralAuthenticate), P1: byte(suite.algorithm), P2: byte(protocol.SecureMessaging),
		Data: bertlv.Append(nil, 0x7c, data), Le: 256, Encoding: iso7816.EncodingShort,
	}
}

func parseEstablishmentResponse(suite cipherSuite, data []byte) (nonce, cryptogram, certificate []byte, err error) {
	value, err := protocol.ParseObject(data, 0x7c)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: establishment template: %v", ErrInvalidResponse, err)
	}

	value, err = protocol.ParseObject(value, 0x82)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: establishment response: %v", ErrInvalidResponse, err)
	}
	// Control byte, suite-sized nonce, 16-byte confirmation, complete CVC.
	certificateOffset := 1 + suite.nonceSize + 16
	if len(value) <= certificateOffset {
		return nil, nil, nil, fmt.Errorf("%w: truncated establishment response", ErrInvalidResponse)
	}

	if value[0] != 0 {
		return nil, nil, nil, fmt.Errorf("%w: unsupported card control byte", ErrAuthentication)
	}

	return value[1 : 1+suite.nonceSize], value[1+suite.nonceSize : certificateOffset], value[certificateOffset:], nil
}

func invalidHandshake(err error) error {
	return &transport.DeviceInvalidatedError{Err: err}
}
