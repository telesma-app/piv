package sm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"github.com/telesma-app/iso7816"
	piviso7816 "github.com/telesma-app/piv/transport/iso7816"
)

type framingVector struct {
	keySize       int
	commandHash   string
	responseHash  string
	commandChain  string
	responseChain string
	nextAPDU      string
	nextResponse  string
}

func TestTransportProtectsBeforeChainingAndAuthenticatesAfterCollection(t *testing.T) {
	// CS2 values were independently calculated with OpenSSL AES-128-ECB,
	// AES-128-CBC (-nopad) and CMAC, using 00..0f / 20..2f / 40..4f keys.
	for _, test := range []struct {
		name   string
		vector framingVector
	}{
		{name: "CS2", vector: framingVector{
			keySize:       16,
			commandHash:   "ad755bd219b9b42dfd8ed7265bb3ef2d00e116e45d9c3277ef32ac80fe5d2f55",
			responseHash:  "07282805b5a90be75fd017612d5d23788e080784de03d548102f835d0f276bca",
			commandChain:  "a0fe93919037090db5e256c84c603287",
			responseChain: "7ac35a96c698ae6d7c32c2173ed8a5d5",
			nextAPDU:      "0c2000800a8e082e441fdbf138a2b300",
			nextResponse:  "990290008e0892c375f4c7e544589000",
		}},
		{name: "CS7", vector: framingVector{
			keySize:       32,
			commandHash:   "8f6a975ee0ad0f1d65d97405d040d37781f0a42c2cb0a08776eeccb866c220e9",
			responseHash:  "9e84d5647e12c8662e8f66b0da26629d33b877e124492acf171dabe80fffc61a",
			commandChain:  "9cb328485f0dcf83d07f6c2dbca975c9",
			responseChain: "963e2f981418553e2c0937c216d76b0f",
			nextAPDU:      "0c2000800a8e08ea746dc6005c882700",
			nextResponse:  "990290008e08e0cbd2cc0c884a859000",
		}},
	} {
		t.Run(test.name, func(t *testing.T) { checkTransportFraming(t, test.vector) })
	}
}

type framingCard struct {
	t          testing.TB
	vector     framingVector
	session    *recordSession
	response   []byte
	command    []byte
	calls      int
	closeCalls int
}

func (c *framingCard) Transmit(_ context.Context, apdu []byte) ([]byte, error) {
	c.t.Helper()

	call := c.calls
	c.calls++

	if call == 0 {
		if !bytes.Equal(apdu, decodeHex(c.t, "00a4040009a0000003080000100000")) {
			c.t.Fatalf("SELECT = %x", apdu)
		}

		return decodeHex(c.t, "61114f0600001000010079074f05a0000003089000"), nil
	}

	wantCounter := byte(1)
	if call == 6 {
		wantCounter = 2
	}

	if c.session.counter != [16]byte{15: wantCounter} {
		c.t.Fatalf("APDU %d advanced counter before logical response: %x", call, c.session.counter)
	}

	switch call {
	case 1, 2:
		if len(apdu) != 260 || !bytes.Equal(apdu[:5], decodeHex(c.t, "1ccb3fffff")) {
			c.t.Fatalf("intermediate command %d = %x", call, apdu)
		}

		c.command = append(c.command, apdu[5:]...)

		return []byte{0x90, 0}, nil
	case 3:
		if len(apdu) != 122 || !bytes.Equal(apdu[:5], decodeHex(c.t, "0ccb3fff74")) || apdu[len(apdu)-1] != 0 {
			c.t.Fatalf("final command fragment = %x", apdu)
		}

		c.command = append(c.command, apdu[5:len(apdu)-1]...)

		digest := sha256.Sum256(c.command)
		if !bytes.Equal(digest[:], decodeHex(c.t, c.vector.commandHash)) {
			c.t.Fatalf("assembled command SHA-256 = %x", digest)
		}

		return append(bytes.Clone(c.response[:256]), 0x61, 0), nil
	case 4:
		if !bytes.Equal(apdu, decodeHex(c.t, "00c0000000")) {
			c.t.Fatalf("first GET RESPONSE = %x, want CLA 00 and Le 256", apdu)
		}

		return append(bytes.Clone(c.response[256:512]), 0x61, 0xd3), nil
	case 5:
		if !bytes.Equal(apdu, decodeHex(c.t, "00c00000d3")) {
			c.t.Fatalf("second GET RESPONSE = %x, want CLA 00 and Le 211", apdu)
		}

		return append(bytes.Clone(c.response[512:]), 0x90, 0), nil
	case 6:
		if !bytes.Equal(apdu, decodeHex(c.t, c.vector.nextAPDU)) {
			c.t.Fatalf("following protected VERIFY = %x", apdu)
		}

		return decodeHex(c.t, c.vector.nextResponse), nil
	default:
		c.t.Fatalf("unexpected APDU %d: %x", call, apdu)
		return nil, nil
	}
}

func (c *framingCard) Close() error {
	c.closeCalls++
	return nil
}

func checkTransportFraming(t *testing.T, vector framingVector) {
	t.Helper()

	keys := recordKeys()
	keys.keySize = vector.keySize

	plaintext := make([]byte, 700)
	for i := range plaintext {
		plaintext[i] = byte(i*7 + 3)
	}

	// One complete encrypted response. The fixed SHA-256 and following APDU
	// vectors were independently generated with OpenSSL 3.5.9, using the same
	// construction and key values documented in the record-vector tests.
	response := []byte{0x87, 0x82, 0x02, 0xc1, 1}
	response = append(response, encrypt(keys.enc[:keys.keySize], [16]byte{0: 0x80, 15: 1}, plaintext)...)
	response = append(response, 0x99, 2, 0x90, 0)
	mac := cmac(keys.rmac[:keys.keySize], append(make([]byte, 16), response...))
	response = append(response, 0x8e, 8)
	response = append(response, mac[:8]...)

	digest := sha256.Sum256(response)
	if !bytes.Equal(digest[:], decodeHex(t, vector.responseHash)) {
		t.Fatalf("protected response SHA-256 = %x", digest)
	}

	raw := &framingCard{t: t, vector: vector, response: response}

	connection, err := piviso7816.Open(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}

	transport := &Transport{
		connection: connection,
		session:    newRecordSession(keys, iso7816.EncodingShort),
		mu:         make(chan struct{}, 1),
		closed:     make(chan struct{}),
	}

	t.Cleanup(func() {
		if err := transport.Close(); err != nil {
			t.Error(err)
		}
	})

	raw.session = &transport.session

	commandData := make([]byte, 600)
	for i := range commandData {
		commandData[i] = byte(i)
	}

	got, err := transport.Exchange(t.Context(), iso7816.Command{INS: 0xcb, P1: 0x3f, P2: 0xff, Data: commandData, Le: 256})
	if err != nil {
		t.Fatal(err)
	}

	if got.Status != iso7816.StatusSuccess || !bytes.Equal(got.Data, plaintext) {
		t.Errorf("assembled authenticated response = status %s data %x", got.Status, got.Data)
	}

	if raw.calls != 6 || transport.session.counter != [16]byte{15: 2} {
		t.Errorf("after chained exchange: raw calls = %d, counter = %x", raw.calls, transport.session.counter)
	}

	if !bytes.Equal(transport.session.commandChain[:], decodeHex(t, vector.commandChain)) || !bytes.Equal(transport.session.responseChain[:], decodeHex(t, vector.responseChain)) {
		t.Errorf("logical command/response chains = %x / %x", transport.session.commandChain, transport.session.responseChain)
	}

	// The next complete exchange uses the previous logical C-MAC and R-MAC,
	// independent of the number of outgoing and incoming fragments.
	got, err = transport.Exchange(t.Context(), iso7816.Command{INS: 0x20, P2: 0x80})
	if err != nil {
		t.Fatal(err)
	}

	if got.Status != iso7816.StatusSuccess || len(got.Data) != 0 || raw.calls != 7 || transport.session.counter != [16]byte{15: 3} {
		t.Errorf("following exchange = %+v, raw calls = %d, counter = %x", got, raw.calls, transport.session.counter)
	}

	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}

	if raw.closeCalls != 1 {
		t.Errorf("raw Close calls = %d, want 1", raw.closeCalls)
	}
}
