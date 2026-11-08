package card

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

// This fixed PKCS#8 fixture comes from Go's crypto/rsa rsa_test.go test2048Key.
// Parse it afresh so each test owns its mutable key state.
const signingRSAFixture = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDNoyFUYeDuqw+k
iyv47iBy/udbWmQdpbUZ8JobHv8uQrvL7sQN6l83teHgNJsXqtiLF3MC+K+XI6Dq
hxUWfQwLip8WEnv7Jx/+53S8yp/CS4Jw86Q1bQHbZjFDpcoqSuwAxlegw18HNZCY
fpipYnA1lYCm+MTjtgXJQbjA0dwUGCf4BDMqt+76Jk3XZF5975rftbkGoT9eu8Jt
Xs5F5Xkwd8q3fkQz+fpLW4u9jrfFyQ61RRFkYrCjlhtGjYIzBHGgQM4n/sNXhiy5
h0tA7Xa6NyYrN/OXe/Y1K8Rz/tzlvbMoxgZgtBuKo1N3m8ckFi7hUVK2eNv7GoAb
teTTPrg/AgMBAAECggEAAnfsVpmsL3R0Bh4gXRpPeM63H6e1a8B8kyVwiO9o0cXX
gKp9+P39izfB0Kt6lyCj/Wg+wOQT7rg5qy1yIw7fBHGmcjquxh3uN0s3YZ+Vcym6
SAY5f0vh/OyJN9r3Uv8+Pc4jtb7So7QDzdWeZurssBmUB0avAMRdGNFGP5SyILcz
l3Q59hTxQ4czRHKjZ06L1/sA+tFVbO1j39FN8nMOU/ovLF4lAmZTkQ6AP6n6XPHP
B8Nq7jSYz6RDO200jzp6UsdrnjjkJRbzOxN/fn+ckCP+WYuq+y/d05ET9PdVa4qI
Jyr80D9QgHmfztcecvYwoskGnkb2F4Tmp0WnAj/xVQKBgQD4TrMLyyHdbAr5hoSi
p+r7qBQxnHxPe2FKO7aqagi4iPEHauEDgwPIcsOYota1ACiSs3BaESdJAClbqPYd
HDI4c2DZ6opux6WYkSju+tVXYW6qarR3fzrP3fUCdz2c2NfruWOqq8YmjzAhTNPm
YzvtzTdwheNYV0Vi71t1SfZmfQKBgQDUAgSUcrgXdGDnSbaNe6KwjY5oZWOQfZe2
DUhqfN/JRFZj+EMfIIh6OQXnZqkp0FeRdfRAFl8Yz8ESHEs4j+TikLJEeOdfmYLS
TWxlMPDTUGbUvSf4g358NJ8TlfYA7dYpSTNPXMRSLtsz1palmaDBTE/V2xKtTH6p
VglRNRUKawKBgCPqBh2TkN9czC2RFkgMb4FcqycN0jEQ0F6TSnVVhtNiAzKmc8s1
POvWJZJDIzjkv/mP+JUeXAdD/bdjNc26EU126rA6KzGgsMPjYv9FymusDPybGGUc
Qt5j5RcpNgEkn/5ZPyAlXjCfjz+RxChTfAyGHRmqU9qoLMIFir3pJ7llAoGBAMNH
sIxENwlzqyafoUUlEq/pU7kZWuJmrO2FwqRDraYoCiM/NCRhxRQ/ng6NY1gejepw
abD2alXiV4alBSxubne6rFmhvA00y2mG40c6Ezmxn2ZpbX3dMQ6bMcPKp7QnXtLc
mCSL4FGK02ImUNDsd0RVVFw51DRId4rmsuJYMK9NAoGAKlYdc4784ixTD2ZICIOC
ZWPxPAyQUEA7EkuUhAX1bVNG6UJTYA8kmGcUCG4jPTgWzi00IyUUr8jK7efyU/zs
qiJuVs1bia+flYIQpysMl1VzZh8gW1nkB4SVPm5l2wBvVJDIr9Mc6rueC/oVNkh2
fLVGuFoTVIu2bF0cWAjNNMg=
-----END PRIVATE KEY-----`

func signingRSA(t testing.TB) *rsa.PrivateKey {
	t.Helper()

	block, _ := pem.Decode([]byte(signingRSAFixture))

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	return parsed.(*rsa.PrivateKey)
}

func signingECDSA(t testing.TB, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return key
}

// signaturePeer models a selected card's VERIFY and raw signature operations.
// Request snapshots own their bytes because client buffers are cleared on return.
type signaturePeer struct {
	t                       testing.TB
	reference               protocol.KeyReference
	algorithm               protocol.Algorithm
	authenticationReference protocol.KeyReference
	authenticationData      []byte
	ec                      *ecdsa.PrivateKey
	rsa                     *rsa.PrivateKey
	instructions            []byte
	inputs                  [][]byte
	verifies                int
	signatures              int
	statuses                int
	afterVerify             func()
	beforeSign              func(context.Context) error
	afterSignature          func()
	response                func([]byte) iso7816.Response
	closed                  chan struct{}
	closeCalls              int
}

func newECDSASigningPeer(t testing.TB, curve elliptic.Curve, reference protocol.KeyReference) (*PrivateKey, *signaturePeer) {
	t.Helper()
	private := signingECDSA(t, curve)

	algorithm := protocol.ECCP256
	if curve == elliptic.P384() {
		algorithm = protocol.ECCP384
	}

	raw := &signaturePeer{
		t: t, reference: reference, algorithm: algorithm, ec: private, closed: make(chan struct{}),
		authenticationReference: protocol.ApplicationPIN,
		authenticationData:      []byte{'1', '2', '3', '4', '5', '6', 0xff, 0xff},
	}
	device := New(raw)

	t.Cleanup(func() { _ = device.Close() })

	key, err := device.PrivateKey(reference, &private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	return key, raw
}

func newRSASigningPeer(t testing.TB) (*PrivateKey, *signaturePeer) {
	t.Helper()
	private := signingRSA(t)
	raw := &signaturePeer{
		t: t, reference: protocol.DigitalSignature, algorithm: protocol.RSA2048,
		rsa: private, closed: make(chan struct{}),
		authenticationReference: protocol.ApplicationPIN,
		authenticationData:      []byte{'1', '2', '3', '4', '5', '6', 0xff, 0xff},
	}
	device := New(raw)

	t.Cleanup(func() { _ = device.Close() })

	key, err := device.PrivateKey(protocol.DigitalSignature, &private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	return key, raw
}

func signatureTLV(tag byte, value []byte) []byte {
	if len(value) < 128 {
		return append([]byte{tag, byte(len(value))}, value...)
	}

	return append([]byte{tag, 0x82, byte(len(value) >> 8), byte(len(value))}, value...)
}

func signatureResponse(signature []byte) iso7816.Response {
	return iso7816.Response{Status: 0x9000, Data: signatureTLV(0x7c, signatureTLV(0x82, signature))}
}

func (p *signaturePeer) Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	p.t.Helper()

	if err := ctx.Err(); err != nil {
		return iso7816.Response{}, err
	}

	select {
	case <-p.closed:
		return iso7816.Response{}, &transport.DeviceInvalidatedError{Err: io.ErrClosedPipe}
	default:
	}

	p.instructions = append(p.instructions, command.INS)
	if command.INS == 0xfd {
		return iso7816.Response{Status: 0x9000}, nil
	}

	if command.INS == byte(protocol.Verify) {
		if command.P1 != 0 || command.P2 != byte(p.authenticationReference) {
			p.t.Errorf("VERIFY header = %+v", command)
			return iso7816.Response{}, io.ErrUnexpectedEOF
		}

		if len(command.Data) == 0 {
			p.statuses++
			return iso7816.Response{Status: 0x63c3}, nil
		}

		p.verifies++

		if !bytes.Equal(command.Data, p.authenticationData) {
			return iso7816.Response{Status: 0x63c2}, nil
		}

		if p.afterVerify != nil {
			p.afterVerify()
		}

		return iso7816.Response{Status: 0x9000}, nil
	}

	if command.INS != byte(protocol.GeneralAuthenticate) || command.P1 != byte(p.algorithm) ||
		command.P2 != byte(p.reference) || command.Le != 256 || command.CLA != 0 {
		p.t.Errorf("unexpected signing command: %+v", command)
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	var prefix []byte
	if p.rsa != nil {
		// Independent RSA-2048 wire oracle: 7C {82 empty, 81 256-byte EM}.
		prefix = []byte{0x7c, 0x82, 1, 6, 0x82, 0, 0x81, 0x82, 1, 0}
	} else {
		width := p.ec.Curve.Params().BitSize / 8
		prefix = []byte{0x7c, byte(width + 4), 0x82, 0, 0x81, byte(width)}
	}

	if !bytes.HasPrefix(command.Data, prefix) {
		p.t.Errorf("signing input prefix = %x, want %x", command.Data, prefix)
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	input := command.Data[len(prefix):]
	if p.rsa != nil && len(input) != p.rsa.Size() {
		p.t.Errorf("RSA input length = %d, want %d", len(input), p.rsa.Size())
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	if p.ec != nil && len(input) != p.ec.Curve.Params().BitSize/8 {
		p.t.Errorf("ECDSA input length = %d, want %d", len(input), p.ec.Curve.Params().BitSize/8)
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	p.inputs = append(p.inputs, bytes.Clone(input))
	if p.beforeSign != nil {
		if err := p.beforeSign(ctx); err != nil {
			return iso7816.Response{}, err
		}
	}

	var signature []byte
	if p.rsa != nil {
		// This is the token's raw RSA primitive, not the host EMSA encoder.
		signature = new(big.Int).Exp(new(big.Int).SetBytes(input), p.rsa.D, p.rsa.N).FillBytes(make([]byte, p.rsa.Size()))
	} else {
		var err error

		signature, err = ecdsa.SignASN1(rand.Reader, p.ec, input)
		if err != nil {
			p.t.Error(err)
			return iso7816.Response{}, err
		}
	}

	p.signatures++
	if p.afterSignature != nil {
		p.afterSignature()
	}

	if p.response != nil {
		return p.response(signature), nil
	}

	return signatureResponse(signature), nil
}

func (p *signaturePeer) Close() error {
	p.closeCalls++
	close(p.closed)

	return nil
}

func signingPIN(context.Context) (string, error) {
	return "123456", nil
}
