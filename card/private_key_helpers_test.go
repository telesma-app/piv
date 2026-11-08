package card

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"testing"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

func newRSADecryptionPeer(t testing.TB) (*PrivateKey, *signaturePeer) {
	t.Helper()
	private := signingRSA(t)
	raw := &signaturePeer{
		t: t, reference: protocol.KeyManagement, algorithm: protocol.RSA2048,
		rsa: private, closed: make(chan struct{}),
		authenticationReference: protocol.ApplicationPIN,
		authenticationData:      []byte{'1', '2', '3', '4', '5', '6', 0xff, 0xff},
	}
	device := New(raw)

	t.Cleanup(func() { _ = device.Close() })

	key, err := device.PrivateKey(protocol.KeyManagement, &private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	return key, raw
}

func rsaCiphertext(t testing.TB, publicKey *rsa.PublicKey, message []byte, opts crypto.DecrypterOpts) []byte {
	t.Helper()

	var ciphertext []byte

	var err error

	if oaep, ok := opts.(*rsa.OAEPOptions); ok {
		ciphertext, err = rsa.EncryptOAEP(oaep.Hash.New(), rand.Reader, publicKey, message, oaep.Label)
	} else {
		ciphertext, err = rsa.EncryptPKCS1v15(rand.Reader, publicKey, message) //nolint:staticcheck // Legacy PIV compatibility requires PKCS#1 v1.5 support.
	}

	if err != nil {
		t.Fatal(err)
	}

	return ciphertext
}

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

// This PKCS#8 fixture is Go 1.27.3 crypto/rsa's test4096Key.
// Parse it afresh so tests own their mutable key state.
const signingRSA4096Fixture = `-----BEGIN PRIVATE KEY-----
MIIJQQIBADANBgkqhkiG9w0BAQEFAASCCSswggknAgEAAoICAQCmH55T2e8fdUaL
iWVL2yI7d/wOu/sxI4nVGoiRMiSMlMZlOEZ4oJY6l2y9N/b8ftwoIpjYO8CBk5au
x2Odgpuz+FJyHppvKakUIeAn4940zoNkRe/iptybIuH5tCBygjs0y1617TlR/c5+
FF5YRkzsEJrGcLqXzj0hDyrwdplBOv1xz2oHYlvKWWcVMR/qgwoRuj65Ef262t/Q
ELH3+fFLzIIstFTk2co2WaALquOsOB6xGOJSAAr8cIAWe+3MqWM8DOcgBuhABA42
9IhbBBw0uqTXUv/TGi6tcF29H2buSxAx/Wm6h2PstLd6IJAbWHAa6oTz87H0S6XZ
v42cYoFhHma1OJw4id1oOZMFDTPDbHxgUnr2puSU+Fpxrj9+FWwViKE4j0YatbG9
cNVpx9xo4NdvOkejWUrqziRorMZTk/zWKz0AkGQzTN3PrX0yy61BoWfznH/NXZ+o
j3PqVtkUs6schoIYvrUcdhTCrlLwGSHhU1VKNGAUlLbNrIYTQNgt2gqvjLEsn4/i
PgS1IsuDHIc7nGjzvKcuR0UeYCDkmBQqKrdhGbdJ1BRohzLdm+woRpjrqmUCbMa5
VWWldJen0YyAlxNILvXMD117azeduseM1sZeGA9L8MmE12auzNbKr371xzgANSXn
jRuyrblAZKc10kYStrcEmJdfNlzYAwIDAQABAoICABdQBpsD0W/buFuqm2GKzgIE
c4Xp0XVy5EvYnmOp4sEru6/GtvUErDBqwaLIMMv8TY8AU+y8beaBPLsoVg1rn8gg
yAklzExfT0/49QkEDFHizUOMIP7wpbLLsWSmZ4tKRV7CT3c+ZDXiZVECML84lmDm
b6H7feQB2EhEZaU7L4Sc76ZCEkIZBoKeCz5JF46EdyxHs7erE61eO9xqC1+eXsNh
Xr9BS0yWV69K4o/gmnS3p2747AHP6brFWuRM3fFDsB5kPScccQlSyF/j7yK+r+qi
arGg/y+z0+sZAr6gooQ8Wnh5dJXtnBNCxSDJYw/DWHAeiyvk/gsndo3ZONlCZZ9u
bpwBYx3hA2wTa5GUQxFM0KlI7Ftr9Cescf2jN6Ia48C6FcQsepMzD3jaMkLir8Jk
/YD/s5KPzNvwPAyLnf7x574JeWuuxTIPx6b/fHVtboDK6j6XQnzrN2Hy3ngvlEFo
zuGYVvtrz5pJXWGVSjZWG1kc9iXCdHKpmFdPj7XhU0gugTzQ/e5uRIqdOqfNLI37
fppSuWkWd5uaAg0Zuhd+2L4LG2GhVdfFa1UeHBe/ncFKz1km9Bmjvt04TpxlRnVG
wHxJZKlxpxCZ3AuLNUMP/QazPXO8OIfGOCbwkgFiqRY32mKDUvmEADBBoYpk/wBv
qV99g5gvYFC5Le4QLzOJAoIBAQDcnqnK2tgkISJhsLs2Oj8vEcT7dU9vVnPSxTcC
M0F+8ITukn33K0biUlA+ktcQaF+eeLjfbjkn/H0f2Ajn++ldT56MgAFutZkYvwxJ
2A6PVB3jesauSpe8aqoKMDIj8HSA3+AwH+yU+yA9r5EdUq1S6PscP+5Wj22+thAa
l65CFD77C0RX0lly5zdjQo3Vyca2HYGm/cshFCPRZc66TPjNAHFthbqktKjMQ91H
Hg+Gun2zv8KqeSzMDeHnef4rVaWMIyIBzpu3QdkKPUXMQQxvJ+RW7+MORV9VjE7Z
KVnHa/6x9n+jvtQ0ydHc2n0NOp6BQghTCB2G3w3JJfmPcRSNAoIBAQDAw6mPddoz
UUzANMOYcFtos4EaWfTQE2okSLVAmLY2gtAK6ldTv6X9xl0IiC/DmWqiNZJ/WmVI
glkp6iZhxBSmqov0X9P0M+jdz7CRnbZDFhQWPxSPicurYuPKs52IC08HgIrwErzT
/lh+qRXEqzT8rTdftywj5fE89w52NPHBsMS07VhFsJtU4aY2Yl8y1PHeumXU6h66
yTvoCLLxJPiLIg9PgvbMF+RiYyomIg75gwfx4zWvIvWdXifQBC88fE7lP2u5gtWL
JUJaMy6LNKHn8YezvwQp0dRecvvoqzoApOuHfsPASHb9cfvcy/BxDXFMJO4QWCi1
6WLaR835nKLPAoIBAFw7IHSjxNRl3b/FaJ6k/yEoZpdRVaIQHF+y/uo2j10IJCqw
p2SbfQjErLNcI/jCCadwhKkzpUVoMs8LO73v/IF79aZ7JR4pYRWNWQ/N+VhGLDCb
dVAL8x9b4DZeK7gGoE34SfsUfY1S5wmiyiHeHIOazs/ikjsxvwmJh3X2j20klafR
8AJe9/InY2plunHz5tTfxQIQ+8iaaNbzntcXsrPRSZol2/9bX231uR4wHQGQGVj6
A+HMwsOT0is5Pt7S8WCCl4b13vdf2eKD9xgK4a3emYEWzG985PwYqiXzOYs7RMEV
cgr8ji57aPbRiJHtPbJ/7ob3z5BA07yR2aDz/0kCggEAZDyajHYNLAhHr98AIuGy
NsS5CpnietzNoeaJEfkXL0tgoXxwQqVyzH7827XtmHnLgGP5NO4tosHdWbVflhEf
Z/dhZYb7MY5YthcMyvvGziXJ9jOBHo7Z8Nowd7Rk41x2EQGfve0QcfBd1idYoXch
y47LL6OReW1Vv4z84Szw1fZ0o1yUPVDzxPS9uKP4uvcOevJUh53isuB3nVYArvK5
p6fjbEY+zaxS33KPdVrajJa9Z+Ptg4/bRqSycTHr2jkN0ZnkC4hkQMH0OfFJb6vD
0VfAaBCZOqHZG/AQ3FFFjRY1P7UEV5WXAn3mKU+HTVJfKug9PxSIvueIttcF3Zm8
8wKCAQAM43+DnGW1w34jpsTAeOXC5mhIz7J8spU6Uq5bJIheEE2AbX1z+eRVErZX
1WsRNPsNrQfdt/b5IKboBbSYKoGxxRMngJI1eJqyj4LxZrACccS3euAlcU1q+3oN
T10qfQol54KjGld/HVDhzbsZJxzLDqvPlroWgwLdOLDMXhwJYfTnqMEQkaG4Aawr
3P14+Zp/woLiPWw3iZFcL/bt23IOa9YI0NoLhp5MFNXfIuzx2FhVz6BUSeVfQ6Ko
Nx2YZ03g6Kt6B6c43LJx1a/zEPYSZcPERgWOSHlcjmwRfTs6uoN9xt1qs4zEUaKv
Axreud3rJ0rekUp6rI1joG717Wls
-----END PRIVATE KEY-----`

func signingRSA4096(t testing.TB) *rsa.PrivateKey {
	t.Helper()

	block, _ := pem.Decode([]byte(signingRSA4096Fixture))

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
	ed                      ed25519.PrivateKey
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
	} else if curve == elliptic.P521() {
		algorithm = protocol.ECCP521
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

func newEd25519SigningPeer(t testing.TB, private ed25519.PrivateKey) (*PrivateKey, *signaturePeer) {
	t.Helper()
	raw := &signaturePeer{
		t: t, reference: protocol.DigitalSignature, algorithm: protocol.Ed25519,
		ed: private, closed: make(chan struct{}),
		authenticationReference: protocol.ApplicationPIN,
		authenticationData:      []byte{'1', '2', '3', '4', '5', '6', 0xff, 0xff},
	}
	device := New(raw)

	t.Cleanup(func() { _ = device.Close() })

	key, err := device.PrivateKey(protocol.DigitalSignature, private.Public())
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

	var input []byte

	if p.ed != nil || (p.ec != nil && p.ec.Curve == elliptic.P521()) {
		tag, value, rest, err := bertlv.Parse(command.Data)
		if err != nil || tag != 0x7c || len(rest) != 0 {
			p.t.Errorf("invalid signing template: %x, %v", command.Data, err)
			return iso7816.Response{}, io.ErrUnexpectedEOF
		}

		tag, response, remaining, err := bertlv.Parse(value)
		if err != nil || tag != 0x82 || len(response) != 0 {
			p.t.Errorf("invalid signing response request: %x, %v", value, err)
			return iso7816.Response{}, io.ErrUnexpectedEOF
		}

		tag, input, rest, err = bertlv.Parse(remaining)
		if err != nil || tag != 0x81 || len(rest) != 0 {
			p.t.Errorf("invalid signing challenge: %x, %v", remaining, err)
			return iso7816.Response{}, io.ErrUnexpectedEOF
		}
	} else {
		var prefix []byte
		if p.rsa != nil {
			// Independent RSA-2048 wire oracle: 7C {82 empty, 81 256-byte EM}.
			prefix = []byte{0x7c, 0x82, 1, 6, 0x82, 0, 0x81, 0x82, 1, 0}
			if p.rsa.Size() == 512 {
				// RSA-4096 uses a 512-byte EM.
				prefix = []byte{0x7c, 0x82, 2, 6, 0x82, 0, 0x81, 0x82, 2, 0}
			}
		} else {
			width := p.ec.Curve.Params().BitSize / 8
			prefix = []byte{0x7c, byte(width + 4), 0x82, 0, 0x81, byte(width)}
		}

		if !bytes.HasPrefix(command.Data, prefix) {
			p.t.Errorf("signing input prefix = %x, want %x", command.Data, prefix)
			return iso7816.Response{}, io.ErrUnexpectedEOF
		}

		input = command.Data[len(prefix):]
	}

	if p.rsa != nil && len(input) != p.rsa.Size() {
		p.t.Errorf("RSA input length = %d, want %d", len(input), p.rsa.Size())
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	if p.ec != nil && p.ec.Curve != elliptic.P521() && len(input) != p.ec.Curve.Params().BitSize/8 {
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
	} else if p.ed != nil {
		signature = ed25519.Sign(p.ed, input)
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
