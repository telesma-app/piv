package card

import (
	"context"
	"crypto"
	"io"
)

type signer struct {
	key            *PrivateKey
	ctx            context.Context
	authentication AuthenticationSource
}

var _ crypto.Signer = (*signer)(nil)

// Signer adapts the key to crypto.Signer using ctx for every signature.
// Create it for the lifetime of the request. Cancellation follows the transport's
// contract; authentication follows [AuthenticationSource]. The adapter borrows
// the key and does not close its Device.
func (key *PrivateKey) Signer(ctx context.Context, authentication AuthenticationSource) crypto.Signer {
	return &signer{key: key, ctx: ctx, authentication: authentication}
}

func (s *signer) Public() crypto.PublicKey {
	return s.key.Public()
}

func (s *signer) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(s.ctx, random, digest, opts, s.authentication)
}
