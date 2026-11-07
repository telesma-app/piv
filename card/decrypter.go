package card

import (
	"context"
	"crypto"
	"io"
)

type decrypter struct {
	key            *PrivateKey
	ctx            context.Context
	authentication AuthenticationSource
}

var _ crypto.Decrypter = (*decrypter)(nil)

// Decrypter adapts the key to crypto.Decrypter using an explicit context and
// authentication source. Create it for the lifetime of the request using it.
// Options and authentication follow Decrypt. The adapter borrows the key and
// does not own or close its Device. Canceling the supplied context cancels
// operations according to the transport's contract.
func (key *PrivateKey) Decrypter(ctx context.Context, authentication AuthenticationSource) crypto.Decrypter {
	return &decrypter{key: key, ctx: ctx, authentication: authentication}
}

func (d *decrypter) Public() crypto.PublicKey {
	return d.key.Public()
}

func (d *decrypter) Decrypt(random io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return d.key.Decrypt(d.ctx, random, ciphertext, opts, d.authentication)
}
