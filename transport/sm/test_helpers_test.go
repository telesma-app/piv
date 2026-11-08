package sm

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"slices"
	"sync"
	"testing"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
)

func decodeHex(t testing.TB, value string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}

	return decoded
}

func testCipherSuite(t testing.TB, algorithm protocol.Algorithm) cipherSuite {
	t.Helper()

	suite, err := selectCipherSuite(algorithm)
	if err != nil {
		t.Fatal(err)
	}

	return suite
}

func testCipherSuites(t *testing.T, run func(*testing.T, cipherSuite)) {
	t.Helper()

	for _, test := range []struct {
		name      string
		algorithm protocol.Algorithm
	}{
		{name: "CS2", algorithm: protocol.CipherSuite2},
		{name: "CS7", algorithm: protocol.CipherSuite7},
	} {
		t.Run(test.name, func(t *testing.T) { run(t, testCipherSuite(t, test.algorithm)) })
	}
}

func fixtureCertificate(t testing.TB, card *ecdh.PublicKey, signer *ecdsa.PrivateKey, issuer [8]byte) []byte {
	t.Helper()

	body := certificateBody(issuer, make([]byte, 16), card.Bytes(), 0)

	return signCertificate(t, body, signer, false)
}

func certificateBody(issuer [8]byte, subject, point []byte, role byte) []byte {
	body := bertlv.Append(nil, 0x5f29, []byte{0x80})
	body = bertlv.Append(body, 0x42, issuer[:])
	body = bertlv.Append(body, 0x5f20, subject)

	oid := []byte{0x2b, 0x81, 4, 0, 0x22}
	if len(point) == 65 {
		oid = []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7}
	}

	public := bertlv.Append(nil, 6, oid)
	public = bertlv.Append(public, 0x86, point)
	body = bertlv.Append(body, 0x7f49, public)

	return bertlv.Append(body, 0x5f4c, []byte{role})
}

func signCertificate(t testing.TB, body []byte, key crypto.PrivateKey, intermediate bool) []byte {
	t.Helper()

	algorithm := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}}

	var (
		signature []byte
		err       error
	)

	if intermediate {
		algorithm = pkix.AlgorithmIdentifier{Algorithm: oidRSASHA256, Parameters: asn1.NullRawValue}
		digest := sha256.Sum256(body)
		signature, err = rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, digest[:])
	} else if key.(*ecdsa.PrivateKey).Curve == elliptic.P256() {
		algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
		digest := sha256.Sum256(body)
		signature, err = ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), digest[:])
	} else {
		digest := sha512.Sum384(body)
		signature, err = ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), digest[:])
	}

	if err != nil {
		t.Fatal(err)
	}

	digitalSignature, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{Algorithm: algorithm, Signature: asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}})
	if err != nil {
		t.Fatal(err)
	}

	return bertlv.Append(nil, 0x7f21, bertlv.Append(body, 0x5f37, digitalSignature))
}

func certificateKeys(t testing.TB) (*ecdh.PrivateKey, *ecdsa.PrivateKey) {
	t.Helper()
	return certificateKeysForSuite(t, testCipherSuite(t, protocol.CipherSuite7))
}

func certificateKeysForSuite(t testing.TB, suite cipherSuite) (*ecdh.PrivateKey, *ecdsa.PrivateKey) {
	t.Helper()

	card, err := suite.curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := ecdsa.GenerateKey(suite.signingCurve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return card, signer
}

type handshakePeer struct {
	t             testing.TB
	suite         cipherSuite
	static        *ecdh.PrivateKey
	signer        *ecdsa.PrivateKey
	issuer        [8]byte
	certificate   []byte
	keys          sessionKeys
	counter       [16]byte
	responseChain [16]byte
	requests      []iso7816.Command
	handshake     func(iso7816.Response) iso7816.Response
	effect        func(context.Context, iso7816.Command) (iso7816.Response, error)
	application   []byte
	closed        chan struct{}
	closeOnce     sync.Once
	closeCalls    int
	closeErr      error
}

func newHandshakePeer(t testing.TB, suite cipherSuite) *handshakePeer {
	t.Helper()

	static, err := suite.curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := ecdsa.GenerateKey(suite.signingCurve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	p := &handshakePeer{
		t: t, suite: suite, static: static, signer: signer, issuer: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		counter: [16]byte{15: 1}, closed: make(chan struct{}),
	}
	p.certificate = fixtureCertificate(t, static.PublicKey(), signer, p.issuer)
	p.application = bertlv.Append(nil, 0x61, []byte{
		0x4f, 1, 1, 0x79, 3, 0x4f, 1, 2,
		0xac, 6, 0x80, 1, byte(suite.algorithm), 6, 1, 0,
	})

	return p
}

func (p *handshakePeer) parameters() Parameters {
	return Parameters{
		CipherSuite: p.suite.algorithm,
		Trust:       Trust{IssuerID: p.issuer, PublicKey: &p.signer.PublicKey},
		HostID:      [8]byte{8, 7, 6, 5, 4, 3, 2, 1}, Encoding: iso7816.EncodingShort,
	}
}

func (p *handshakePeer) Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	if err := ctx.Err(); err != nil {
		return iso7816.Response{}, err
	}

	copy := command
	copy.Data = slices.Clone(command.Data)

	p.requests = append(p.requests, copy)
	if command.INS == 0xa4 {
		return iso7816.Response{Data: p.application, Status: 0x9000}, nil
	}

	if command.CLA == 0 && command.INS == 0x87 {
		p.t.Helper()

		if command.P1 != byte(p.suite.algorithm) || command.P2 != 4 || command.Encoding != iso7816.EncodingShort || command.Le != 256 {
			p.t.Fatalf("establishment command = %+v", command)
		}

		body, err := protocol.ParseObject(command.Data, 0x7c)
		if err != nil {
			p.t.Fatal(err)
		}

		tag, challenge, rest, err := bertlv.Parse(body)
		if err != nil || tag != 0x81 || len(challenge) != 9+len(p.static.PublicKey().Bytes()) || challenge[0] != 0 || !bytes.Equal(rest, []byte{0x82, 0}) {
			p.t.Fatalf("establishment data = %x, %v", body, err)
		}

		hostID := [8]byte(challenge[1:9])
		public := challenge[9:]

		key, err := p.suite.curve.NewPublicKey(public)
		if err != nil {
			p.t.Fatal(err)
		}

		z, err := p.static.ECDH(key)
		if err != nil {
			p.t.Fatal(err)
		}
		defer clear(z)

		nonce := bytes.Repeat([]byte{0x42}, p.suite.nonceSize)
		id := sha256.Sum256(p.certificate)
		p.keys = deriveKeys(p.suite, z, hostID, [8]byte(id[:8]), public, nonce)
		confirmation := append([]byte("KC_1_V"), id[:8]...)
		confirmation = append(confirmation, hostID[:]...)
		confirmation = append(confirmation, public[1:]...)
		cryptogram := cmac(p.keys.cfrm[:p.keys.keySize], confirmation)

		data := append([]byte{0}, nonce...)
		data = append(data, cryptogram[:]...)
		data = append(data, p.certificate...)

		response := iso7816.Response{Data: bertlv.Append(nil, 0x7c, bertlv.Append(nil, 0x82, data)), Status: 0x9000}
		if p.handshake != nil {
			response = p.handshake(response)
		}

		return response, nil
	}

	if p.effect != nil {
		return p.effect(ctx, command)
	}

	return p.protectedResponse([]byte("public object"), 0x9000), nil
}

func (p *handshakePeer) protectedResponse(plaintext []byte, status iso7816.StatusWord) iso7816.Response {
	var data []byte

	if len(plaintext) != 0 {
		counter := p.counter
		counter[0] = 0x80
		data = bertlv.Append(nil, 0x87, append([]byte{1}, encrypt(p.keys.enc[:p.keys.keySize], counter, plaintext)...))
	}

	data = append(data, 0x99, 2, status.SW1(), status.SW2())
	mac := cmac(p.keys.rmac[:p.keys.keySize], append(p.responseChain[:], data...))
	data = bertlv.Append(data, 0x8e, mac[:8])
	p.responseChain = mac
	p.counter[15]++

	return iso7816.Response{Data: data, Status: 0x9000}
}

func (p *handshakePeer) Close() error {
	p.closeCalls++
	p.closeOnce.Do(func() { close(p.closed) })

	return p.closeErr
}

func openHandshakePeer(t testing.TB, p *handshakePeer) *Transport {
	t.Helper()

	channel, err := Open(t.Context(), p, p.parameters())
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = channel.Close() })

	return channel
}

func readCommand() iso7816.Command {
	return iso7816.Command{INS: 0xcb, P1: 0x3f, P2: 0xff, Data: []byte{0x5c, 1, 0x7e}, Le: 256}
}

func recordKeys() sessionKeys {
	keys := sessionKeys{keySize: 32}
	for i := range 32 {
		keys.enc[i] = byte(i)
		keys.mac[i] = byte(i + 32)
		keys.rmac[i] = byte(i + 64)
	}

	return keys
}

func mutateCertificate(raw []byte, index int) []byte {
	mutated := bytes.Clone(raw)
	mutated[index] ^= 1

	return mutated
}

func appendAlgorithmMembers(t testing.TB, signature, extra []byte) []byte {
	t.Helper()

	_, value, _, err := bertlv.Parse(signature)
	if err != nil {
		t.Fatal(err)
	}

	_, algorithm, rest, err := bertlv.Parse(value)
	if err != nil {
		t.Fatal(err)
	}

	algorithm = append(bytes.Clone(algorithm), extra...)
	value = append(bertlv.Append(nil, 0x30, algorithm), rest...)

	return bertlv.Append(nil, 0x30, value)
}
