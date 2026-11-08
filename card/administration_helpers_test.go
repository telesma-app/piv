package card

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"io"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

type administrationVector struct {
	name       string
	algorithm  protocol.Algorithm
	key        string
	witness    string
	ciphertext string
}

// AES vectors are from FIPS 197, Appendix C.1-C.3. The Triple-DES vector is
// encryptTripleDESTests ("abcdefgh12345678ABCDEFGH") in Go's crypto/des tests.
var administrationVectors = []administrationVector{
	{
		name: "AES-128", algorithm: protocol.AES128,
		key: "000102030405060708090a0b0c0d0e0f", witness: "00112233445566778899aabbccddeeff",
		ciphertext: "69c4e0d86a7b0430d8cdb78070b4c55a",
	},
	{
		name: "AES-192", algorithm: protocol.AES192,
		key: "000102030405060708090a0b0c0d0e0f1011121314151617", witness: "00112233445566778899aabbccddeeff",
		ciphertext: "dda97ca4864cdfe06eaf70a0ec0d7191",
	},
	{
		name: "AES-256", algorithm: protocol.AES256,
		key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", witness: "00112233445566778899aabbccddeeff",
		ciphertext: "8ea2b7ca516745bfeafc49904b496089",
	},
	{
		name: "Triple-DES", algorithm: protocol.TripleDES,
		key: "616263646566676831323334353637384142434445464748", witness: "3030303030303030",
		ciphertext: "e461b759688bff66",
	},
	{
		name: "Triple-DES legacy 00", algorithm: protocol.TripleDESLegacy,
		key: "616263646566676831323334353637384142434445464748", witness: "3030303030303030",
		ciphertext: "e461b759688bff66",
	},
}

func administrationBytes(t testing.TB, encoded string) []byte {
	t.Helper()

	b, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}

	return b
}

// administrationPeer models the two-command mutual authentication, independently
// checks its wire layout, and answers the random challenge using stdlib crypto.
type administrationPeer struct {
	t               testing.TB
	key             AdministrationKey
	block           cipher.Block
	witness         []byte
	encrypted       []byte
	requests        [][]byte
	challenges      [][]byte
	witnessReply    []byte
	proofReply      func([]byte) iso7816.Response
	reject          int
	phase           int
	authenticated   bool
	authentications int
	afterWitness    func()
	afterProof      func()
	effect          func(context.Context, iso7816.Command) (iso7816.Response, error)
	effects         int
	closed          chan struct{}
	closeCalls      int
	closeErr        error
}

func newAdministrationPeer(t testing.TB, vector administrationVector) (*Device, *administrationPeer) {
	t.Helper()
	key := AdministrationKey{Algorithm: vector.algorithm, Key: administrationBytes(t, vector.key)}

	var block cipher.Block

	var err error
	if vector.algorithm == protocol.TripleDESLegacy || vector.algorithm == protocol.TripleDES {
		block, err = des.NewTripleDESCipher(key.Key)
	} else {
		block, err = aes.NewCipher(key.Key)
	}

	if err != nil {
		t.Fatal(err)
	}

	raw := &administrationPeer{
		t: t, key: key, block: block,
		witness: administrationBytes(t, vector.witness), encrypted: administrationBytes(t, vector.ciphertext),
		closed: make(chan struct{}),
	}
	d := New(raw)

	t.Cleanup(func() { _ = d.Close() })

	return d, raw
}

func administrationReply(tag byte, value []byte) iso7816.Response {
	data := append([]byte{0x7c, byte(len(value) + 2), tag, byte(len(value))}, value...)
	return iso7816.Response{Status: 0x9000, Data: data}
}

func (p *administrationPeer) Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	p.t.Helper()

	if err := ctx.Err(); err != nil {
		return iso7816.Response{}, err
	}

	select {
	case <-p.closed:
		return iso7816.Response{}, &transport.DeviceInvalidatedError{Err: io.ErrClosedPipe}
	default:
	}

	raw, err := command.MarshalBinary()
	if err != nil {
		p.t.Error(err)
		return iso7816.Response{}, err
	}
	// MarshalBinary owns this snapshot; GeneralAuthenticate clears command.Data.
	p.requests = append(p.requests, raw)

	if command.INS == 0xfd {
		return iso7816.Response{Status: 0x9000}, nil
	}

	if command.INS != byte(protocol.GeneralAuthenticate) {
		if !p.authenticated {
			p.t.Error("administrative command ran without mutual authentication")
			return iso7816.Response{}, io.ErrUnexpectedEOF
		}

		p.effects++
		if p.effect == nil {
			p.t.Errorf("unexpected administrative command: %x", raw)
			return iso7816.Response{}, io.ErrUnexpectedEOF
		}

		return p.effect(ctx, command)
	}

	if command.P1 != byte(p.key.Algorithm) || command.P2 != 0x9b || command.Le != 256 {
		p.t.Errorf("administration APDU header = %x", raw[:4])
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	if bytes.Equal(command.Data, []byte{0x7c, 2, 0x80, 0}) {
		p.phase = 1

		p.authenticated = false
		if p.reject == 1 {
			return iso7816.Response{Status: 0x6982}, nil
		}

		if p.afterWitness != nil {
			p.afterWitness()
		}

		if p.witnessReply != nil {
			return iso7816.Response{Status: 0x9000, Data: p.witnessReply}, nil
		}

		return administrationReply(0x80, p.encrypted), nil
	}

	if p.phase != 1 {
		p.t.Error("administration completion was sent without a witness request")
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	n := p.block.BlockSize()

	data := command.Data
	if len(data) != 2*n+8 || !bytes.Equal(data[:4], []byte{0x7c, byte(2*n + 6), 0x80, byte(n)}) ||
		!bytes.Equal(data[4:4+n], p.witness) || !bytes.Equal(data[4+n:6+n], []byte{0x81, byte(n)}) ||
		!bytes.Equal(data[6+2*n:], []byte{0x82, 0}) {
		p.t.Errorf("invalid mutual authentication completion: %x", data)
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	p.phase = 0
	if p.reject == 2 {
		return iso7816.Response{Status: 0x6982}, nil
	}

	challenge := bytes.Clone(data[6+n : 6+2*n])
	p.challenges = append(p.challenges, challenge)
	proof := make([]byte, n)
	p.block.Encrypt(proof, challenge)
	p.authenticated = true

	p.authentications++
	if p.afterProof != nil {
		p.afterProof()
	}

	if p.proofReply != nil {
		return p.proofReply(proof), nil
	}

	return administrationReply(0x82, proof), nil
}

func (p *administrationPeer) Close() error {
	p.closeCalls++
	close(p.closed)

	return p.closeErr
}
