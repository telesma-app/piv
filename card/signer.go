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

// Signer adapts the key to crypto.Signer using an explicit context and
// authentication source. Create an adapter for the lifetime of the request using
// it. Canceling that context cancels subsequent and active signing operations
// according to the transport's contract; no background context is substituted.
//
// The source is called for each Sign. Its returned data is owned and cleared by
// that operation according to AuthenticationSource's contract. A nil source
// explicitly disables VERIFY. The adapter borrows the key and does not own or
// close its Device.
func (key *PrivateKey) Signer(ctx context.Context, authentication AuthenticationSource) crypto.Signer {
	return &signer{key: key, ctx: ctx, authentication: authentication}
}

func (s *signer) Public() crypto.PublicKey {
	return s.key.Public()
}

func (s *signer) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(s.ctx, random, digest, opts, s.authentication)
}
