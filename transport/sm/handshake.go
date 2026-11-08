package sm

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"slices"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

func establish(ctx context.Context, connection transport.Device, parameters Parameters, suite cipherSuite) (sessionKeys, protocol.ApplicationPropertyTemplate, error) {
	response, err := connection.Exchange(ctx, protocol.SelectCommand())
	if err != nil {
		return sessionKeys{}, protocol.ApplicationPropertyTemplate{}, err
	}

	if err := response.APDUError(); err != nil {
		return sessionKeys{}, protocol.ApplicationPropertyTemplate{}, fmt.Errorf("sm: SELECT PIV: %w", err)
	}

	application, err := protocol.ParseApplicationPropertyTemplate(response.Data)
	if err != nil {
		return sessionKeys{}, protocol.ApplicationPropertyTemplate{}, err
	}

	// Retain borrowed SELECT fields before the connection reuses response storage.
	application.AID = bytes.Clone(application.AID)
	application.TagAllocationAuthorityAID = bytes.Clone(application.TagAllocationAuthorityAID)

	if !slices.Contains(application.Algorithms, suite.algorithm) {
		return sessionKeys{}, protocol.ApplicationPropertyTemplate{}, fmt.Errorf("sm: selected PIV application does not advertise cipher suite %02X", byte(suite.algorithm))
	}

	ephemeral, err := suite.curve.GenerateKey(rand.Reader)
	if err != nil {
		return sessionKeys{}, protocol.ApplicationPropertyTemplate{}, err
	}

	public := ephemeral.PublicKey().Bytes()

	response, err = connection.Exchange(ctx, establishmentCommand(suite, parameters.HostID, public))
	if err != nil {
		return sessionKeys{}, protocol.ApplicationPropertyTemplate{}, err
	}

	if err := response.APDUError(); err != nil {
		return sessionKeys{}, protocol.ApplicationPropertyTemplate{}, fmt.Errorf("sm: GENERAL AUTHENTICATE: %w", err)
	}

	nonce, cryptogram, certificate, err := parseEstablishmentResponse(suite, response.Data)
	if err != nil {
		return sessionKeys{}, protocol.ApplicationPropertyTemplate{}, invalidHandshake(err)
	}

	peer, err := verifyCertificate(suite, certificate, parameters.Trust)
	if err != nil {
		return sessionKeys{}, protocol.ApplicationPropertyTemplate{}, invalidHandshake(err)
	}

	z, err := ephemeral.ECDH(peer)
	if err != nil {
		return sessionKeys{}, protocol.ApplicationPropertyTemplate{}, invalidHandshake(err)
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
		return sessionKeys{}, protocol.ApplicationPropertyTemplate{}, invalidHandshake(ErrAuthentication)
	}

	return keys, application, nil
}

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
