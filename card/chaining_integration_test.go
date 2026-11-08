package card

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	piviso7816 "github.com/telesma-app/piv/transport/iso7816"
)

func TestEd25519SignChainsShortAPDUs(t *testing.T) {
	// RFC 8032, Section 7.1, test 1 supplies the fixed key; the longer message
	// exercises three command fragments through the real ISO 7816 transport.
	private := ed25519.NewKeyFromSeed([]byte{
		0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
		0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
	})

	message := make([]byte, 600)
	for i := range message {
		message[i] = byte(i)
	}

	want := ed25519.Sign(private, message)

	// 7C {82 empty, 81 600-byte message}, independently encoded and split
	// into 255, 255 and 100 data bytes. Only the final APDU requests Le=256.
	payload := append([]byte{0x7c, 0x82, 0x02, 0x5e, 0x82, 0, 0x81, 0x82, 0x02, 0x58}, message...)
	response := append([]byte{0x7c, 0x42, 0x82, 0x40}, want...)
	response = append(response, 0x90, 0)
	raw := &chainedSigningTransport{t: t, steps: []chainedSigningStep{
		{request: append([]byte{0x10, 0x87, 0xe0, 0x9c, 0xff}, payload[:255]...), response: []byte{0x90, 0}},
		{request: append([]byte{0x10, 0x87, 0xe0, 0x9c, 0xff}, payload[255:510]...), response: []byte{0x90, 0}},
		{request: append(append([]byte{0, 0x87, 0xe0, 0x9c, 0x64}, payload[510:]...), 0), response: response},
	}}
	device := New(raw)

	t.Cleanup(func() { _ = device.Close() })

	key, err := device.PrivateKey(protocol.DigitalSignature, private.Public())
	if err != nil {
		t.Fatal(err)
	}

	got, err := key.Sign(t.Context(), nil, message, crypto.Hash(0), nil)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) || !ed25519.Verify(private.Public().(ed25519.PublicKey), message, got) {
		t.Errorf("signature = %x, want signature of the complete message %x", got, want)
	}

	if len(raw.steps) != 0 {
		t.Errorf("remaining APDU exchanges = %d, want 0", len(raw.steps))
	}
}

func TestRSA4096SignChainsCommandAndCollectsResponse(t *testing.T) {
	private := signingRSA4096(t)
	digest := sha256.Sum256([]byte("RSA-4096 PIV signature"))

	want, err := rsa.SignPKCS1v15(nil, private, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	// Recover the expected encoded message through the RSA public primitive,
	// independently of the host-side PKCS#1 encoder under test.
	em := new(big.Int).Exp(new(big.Int).SetBytes(want), big.NewInt(int64(private.E)), private.N).FillBytes(make([]byte, 512))
	payload := append([]byte{0x7c, 0x82, 0x02, 0x06, 0x82, 0, 0x81, 0x82, 0x02, 0}, em...)
	response := append([]byte{0x7c, 0x82, 0x02, 0x04, 0x82, 0x82, 0x02, 0}, want...)
	raw := &chainedSigningTransport{t: t, steps: []chainedSigningStep{
		{request: append([]byte{0x10, 0x87, 0x16, 0x9c, 0xff}, payload[:255]...), response: []byte{0x90, 0}},
		{request: append([]byte{0x10, 0x87, 0x16, 0x9c, 0xff}, payload[255:510]...), response: []byte{0x90, 0}},
		{
			request:  append(append([]byte{0, 0x87, 0x16, 0x9c, 0x0c}, payload[510:]...), 0),
			response: append(bytes.Clone(response[:256]), 0x61, 0),
		},
		{request: []byte{0, 0xc0, 0, 0, 0}, response: append(bytes.Clone(response[256:512]), 0x61, 8)},
		{request: []byte{0, 0xc0, 0, 0, 8}, response: append(bytes.Clone(response[512:]), 0x90, 0)},
	}}
	device := New(raw)

	t.Cleanup(func() { _ = device.Close() })

	key, err := device.PrivateKey(protocol.DigitalSignature, &private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	got, err := key.Sign(t.Context(), nil, digest[:], crypto.SHA256, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("signature = %x, want complete RSA-4096 signature %x", got, want)
	}

	if len(raw.steps) != 0 {
		t.Errorf("remaining APDU exchanges = %d, want 0", len(raw.steps))
	}
}

type chainedSigningStep struct {
	request  []byte
	response []byte
}

type chainedSigningTransport struct {
	t     testing.TB
	steps []chainedSigningStep
}

func (transport *chainedSigningTransport) Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	return piviso7816.Exchange(ctx, transport, command)
}

func (transport *chainedSigningTransport) Transmit(_ context.Context, apdu []byte) ([]byte, error) {
	transport.t.Helper()

	if len(transport.steps) == 0 {
		transport.t.Fatalf("unexpected APDU: %x", apdu)
	}

	step := transport.steps[0]

	transport.steps = transport.steps[1:]
	if !bytes.Equal(apdu, step.request) {
		transport.t.Fatalf("APDU = %x, want %x", apdu, step.request)
	}

	return step.response, nil
}

func (*chainedSigningTransport) Close() error {
	return nil
}
