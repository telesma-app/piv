package card

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"

	"github.com/telesma-app/piv/internal/decryption"
	"github.com/telesma-app/piv/protocol"
)

// RSA key transport: SP 800-73-5 Part 2, Appendix A.5.1.

// Decrypt decrypts a modulus-sized RSA ciphertext. A nil opts or
// *rsa.PKCS1v15DecryptOptions selects PKCS#1 v1.5; *rsa.OAEPOptions selects OAEP
// with its explicit Hash, MGFHash, and Label. Supported hashes are SHA-1,
// SHA-224/256/384/512, SHA-512/224, SHA-512/256, and SHA3-224/256/384/512.
// Other option types, unsupported hashes, and invalid input are rejected before
// calling the authentication source or card. Ciphertext, options, and label are
// borrowed for the call and must not be modified while it is in progress.
//
// A positive SessionKeyLen must fit the RSA encoding. Random fills a fallback
// key before authentication; valid padding with the requested plaintext length
// replaces it in constant time. Invalid padding or a different length returns
// that random key without an error. The surrounding legacy protocol must not
// reveal which key was used. With SessionKeyLen zero, invalid PKCS#1 v1.5 padding
// returns rsa.ErrDecryption and can expose a padding oracle. Prefer OAEP for new
// protocols. Random is unused in OAEP and ordinary PKCS#1 v1.5 modes and may be nil.
//
// Authentication follows [AuthenticationSource].
//
// Malformed or wrong-sized card results match protocol.ErrInvalidResponse;
// invalid padding matches rsa.ErrDecryption. SessionKeyLen does not hide card,
// authentication, or transport errors. Unlike Sign, Decrypt does not prove that
// the response corresponds to the bound public key. The returned plaintext
// belongs to the caller; temporary encoded-message storage is cleared.
func (key *PrivateKey) Decrypt(
	ctx context.Context,
	random io.Reader,
	ciphertext []byte,
	opts crypto.DecrypterOpts,
	authentication AuthenticationSource,
) (plaintext []byte, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	publicKey, ok := key.publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("piv: RSA decryption requires an RSA key")
	}

	var oaep *rsa.OAEPOptions

	var sessionKeyLen int

	switch options := opts.(type) {
	case nil:
	case *rsa.PKCS1v15DecryptOptions: //nolint:staticcheck // Legacy PIV compatibility requires PKCS#1 v1.5 support.
		sessionKeyLen = options.SessionKeyLen
		if sessionKeyLen < 0 || sessionKeyLen > publicKey.Size()-11 {
			return nil, fmt.Errorf("piv: invalid RSA session key length %d", sessionKeyLen)
		}
	case *rsa.OAEPOptions:
		if err := decryption.ValidateOAEP(publicKey.Size(), options); err != nil {
			return nil, err
		}

		oaep = options
	default:
		return nil, fmt.Errorf("piv: unsupported decryption options %T", opts)
	}

	if len(ciphertext) != publicKey.Size() || new(big.Int).SetBytes(ciphertext).Cmp(publicKey.N) >= 0 {
		return nil, rsa.ErrDecryption
	}

	var sessionKey []byte
	if sessionKeyLen > 0 {
		sessionKey = make([]byte, sessionKeyLen)

		defer func() {
			if err != nil {
				clear(sessionKey)
			}
		}()

		if _, err := io.ReadFull(random, sessionKey); err != nil {
			return nil, fmt.Errorf("piv: RSA session key fallback: %w", err)
		}
	}

	var request protocol.VerifyRequest
	if authentication != nil {
		request, err = authentication(ctx)
		if err != nil {
			return nil, err
		}
		defer clear(request.Data)
	}

	if err := key.device.lock(ctx); err != nil {
		return nil, err
	}
	defer key.device.unlock()

	if authentication != nil {
		if err := key.device.client.Verify(ctx, request); err != nil {
			return nil, key.device.operationError(err)
		}
	}

	response, err := key.device.client.GeneralAuthenticate(ctx, key.algorithm, key.reference, protocol.DynamicAuthentication{
		Challenge: ciphertext, Response: []byte{},
	})
	if err != nil {
		return nil, key.device.operationError(err)
	}
	defer clear(response.Response)
	defer clear(response.Witness)
	defer clear(response.Challenge)
	defer clear(response.Exponentiation)

	if len(response.Response) != publicKey.Size() || response.Witness != nil || response.Challenge != nil || response.Exponentiation != nil {
		return nil, fmt.Errorf("%w: invalid decryption response", protocol.ErrInvalidResponse)
	}

	if oaep != nil {
		return decryption.OAEP(response.Response, oaep)
	}

	if sessionKeyLen > 0 {
		decryption.PKCS1v15SessionKey(response.Response, sessionKey)
		return sessionKey, nil
	}

	return decryption.PKCS1v15(response.Response)
}

type decrypter struct {
	key            *PrivateKey
	ctx            context.Context
	authentication AuthenticationSource
}

var _ crypto.Decrypter = (*decrypter)(nil)

// Decrypter adapts the key to crypto.Decrypter using ctx for every decryption.
// Create it for the lifetime of the request. Cancellation follows the transport's
// contract; options follow Decrypt and authentication follows [AuthenticationSource].
// The adapter borrows the key and does not close its Device.
func (key *PrivateKey) Decrypter(ctx context.Context, authentication AuthenticationSource) crypto.Decrypter {
	return &decrypter{key: key, ctx: ctx, authentication: authentication}
}

func (d *decrypter) Public() crypto.PublicKey {
	return d.key.Public()
}

func (d *decrypter) Decrypt(random io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return d.key.Decrypt(d.ctx, random, ciphertext, opts, d.authentication)
}
