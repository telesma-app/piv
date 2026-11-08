package sm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/telesma-app/iso7816"
)

func recordHex(t testing.TB, value string) []byte {
	t.Helper()

	data, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}

	return data
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

type recordVector struct {
	command   iso7816.Command
	protected string
	cmac      string
	response  string
	rmac      string
	plaintext string
	status    iso7816.StatusWord
}

// These CS7 vectors use the NIST SP 800-73pt2-5 section 4.2 construction.
// AES-256-ECB, AES-256-CBC (-nopad), and CMAC results were independently
// calculated with OpenSSL 3.5.9. Keys are 00..1f, 20..3f, and 40..5f.
func TestRecordVectors(t *testing.T) {
	tests := []recordVector{
		{
			command:   iso7816.Command{INS: 0xcb, P1: 0x3f, P2: 0xff, Data: recordHex(t, "5c017e"), Le: 256},
			protected: "871101b96792d98745219f449f62ad46d845d49701008e08743b85305ccd6bea",
			cmac:      "743b85305ccd6beae81e33ffdc49966f",
			response:  "872101ec0be757fe838d768f1362238a19a718761c2481b8a50d8924263c195fa87263990290008e08190ea8a6548b0e15",
			rmac:      "190ea8a6548b0e15d0a9bf09ec07dde9",
			plaintext: "7e108808a000000308000010005f2f024000",
			status:    0x9000,
		},
		{
			command:   iso7816.Command{INS: 0x20, P2: 0x80},
			protected: "8e08ee9fa5d187e5d651",
			cmac:      "ee9fa5d187e5d6516bc7338df123f299",
			response:  "990263c38e088134a90672d326c6",
			rmac:      "8134a90672d326c62859bd07b15cc50b",
			status:    0x63c3,
		},
		{
			command:   iso7816.Command{INS: 0x20, P2: 0x80, Data: recordHex(t, "313233343536ffff")},
			protected: "871101c9c362e04342f43b4b8ccd378e5188348e08d85b513128a8c2c2",
			cmac:      "d85b513128a8c2c29646ee9debabae68",
			response:  "990290008e08778c3134b1df66fc",
			rmac:      "778c3134b1df66fc6117b6991a1bddfc",
			status:    0x9000,
		},
	}

	checkRecordVectors(t, 32, tests)
}

func checkRecordVectors(t *testing.T, keySize int, tests []recordVector) {
	t.Helper()

	for _, encoding := range []iso7816.Encoding{iso7816.EncodingShort, iso7816.EncodingExtended} {
		keys := recordKeys()
		keys.keySize = keySize
		session := newRecordSession(keys, encoding)

		for i, test := range tests {
			before := session

			protected, next, err := session.protect(test.command)
			if err != nil {
				t.Fatalf("protect vector %d: %v", i, err)
			}

			if !bytes.Equal(protected.Data, recordHex(t, test.protected)) {
				t.Errorf("vector %d protected data = %x, want %s", i, protected.Data, test.protected)
			}

			if protected.CLA != 0x0c || protected.INS != test.command.INS || protected.P1 != test.command.P1 || protected.P2 != test.command.P2 || protected.Le != 256 || protected.Encoding != encoding {
				t.Errorf("vector %d protected header = %+v", i, protected)
			}

			if !bytes.Equal(next[:], recordHex(t, test.cmac)) {
				t.Errorf("vector %d C-MAC = %x, want %s", i, next, test.cmac)
			}

			if session != before {
				t.Errorf("vector %d protect committed state before transmission", i)
			}

			response, err := session.unprotect(iso7816.Response{Data: recordHex(t, test.response), Status: 0x9000}, next)
			if err != nil {
				t.Fatalf("unprotect vector %d: %v", i, err)
			}

			if !bytes.Equal(response.Data, recordHex(t, test.plaintext)) || response.Status != test.status {
				t.Errorf("vector %d response = %+v, want data %s status %s", i, response, test.plaintext, test.status)
			}

			if !bytes.Equal(session.responseChain[:], recordHex(t, test.rmac)) || session.commandChain != next {
				t.Errorf("vector %d MAC chains = %x / %x", i, session.commandChain, session.responseChain)
			}

			if session.counter != [16]byte{15: byte(i + 2)} {
				t.Errorf("vector %d counter = %x", i, session.counter)
			}
		}
	}
}

func TestCS2RecordVectors(t *testing.T) {
	// Independent OpenSSL AES-128-ECB/CBC and CMAC oracle for Section 4.2.
	// Keys are 00..0f, 20..2f and 40..4f; the records form one session.
	checkRecordVectors(t, 16, []recordVector{
		{
			command:   iso7816.Command{INS: 0xcb, P1: 0x3f, P2: 0xff, Data: recordHex(t, "5c017e"), Le: 256},
			protected: "87110132bfc827cc8643fe7f8514f87073f3769701008e0896035c77c12408cc",
			cmac:      "96035c77c12408cc0a0cb833dd519ae6",
			response:  "8721017226ad8cf78d3b1790a3fb4f7566421e6854f7fdf5aa63bdb99d9b2949d2eab2990290008e08f64830abfc5cab24",
			rmac:      "f64830abfc5cab243a3a936c7c875a0f",
			plaintext: "7e108808a000000308000010005f2f024000", status: 0x9000,
		},
		{
			command:   iso7816.Command{INS: 0x20, P2: 0x80},
			protected: "8e08d9cb070c1238dcf9", cmac: "d9cb070c1238dcf9671cf2be28cc7f37",
			response: "990263c38e082211fdf3c4ec0193", rmac: "2211fdf3c4ec0193cc55eda56214b92c",
			status: 0x63c3,
		},
		{
			command:   iso7816.Command{INS: 0x20, P2: 0x80, Data: recordHex(t, "313233343536ffff")},
			protected: "8711015fb5c07e8a2d333a8bf38798c82dfb588e08d9bffc851718c842",
			cmac:      "d9bffc851718c842f8e8acfcb55718be",
			response:  "990290008e08956695fc17e11dac", rmac: "956695fc17e11dac3bdcc6e7609d04d8",
			status: 0x9000,
		},
	})
}

func TestRecordProtectsBeforeFragmentation(t *testing.T) {
	data := make([]byte, 250)
	for i := range data {
		data[i] = byte(i)
	}

	session := newRecordSession(recordKeys(), iso7816.EncodingShort)

	protected, next, err := session.protect(iso7816.Command{INS: 0x87, P1: 0x3f, P2: 0x9a, Data: data, Le: 256})
	if err != nil {
		t.Fatal(err)
	}

	// Independent OpenSSL vector: one complete DO87, DO97 and DO8E.
	digest := sha256.Sum256(protected.Data)
	if !bytes.Equal(digest[:], recordHex(t, "08b5c399ad4dd27f28a32ca9de9138122683ecfe30b193e58ef829a853c255a7")) {
		t.Errorf("protected command SHA-256 = %x", digest)
	}

	if !bytes.Equal(next[:], recordHex(t, "c8181dbfc7c5732d4722bd25109219bc")) {
		t.Errorf("complete command C-MAC = %x", next)
	}

	fragments, err := iso7816.Chain(protected, 261)
	if err != nil {
		t.Fatal(err)
	}

	if len(fragments) != 2 {
		t.Fatalf("fragment count = %d, want 2", len(fragments))
	}

	if fragments[0].CLA != 0x1c || fragments[0].Le != 0 || len(fragments[0].Data) != 255 || fragments[1].CLA != 0x0c || fragments[1].Le != 256 || len(fragments[1].Data) != 19 {
		t.Errorf("fragments = %+v", fragments)
	}

	if !bytes.Equal(append(fragments[0].Data, fragments[1].Data...), protected.Data) {
		t.Error("fragmentation changed protected logical command")
	}

	if session.counter != [16]byte{15: 1} {
		t.Errorf("counter advanced while preparing fragments: %x", session.counter)
	}
}

func TestRecordRejectsMalformedResponses(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{name: "empty"},
		{name: "bare status", data: "9000"},
		{name: "missing MAC", data: "99029000"},
		{name: "MAC before status", data: "8e08000000000000000099029000"},
		{name: "duplicate status", data: "99029000990290008e080000000000000000"},
		{name: "unknown tag", data: "85009000990290008e080000000000000000"},
		{name: "bad status length", data: "99039000008e080000000000000000"},
		{name: "short MAC", data: "990290008e0700000000000000"},
		{name: "long MAC", data: "990290008e09000000000000000000"},
		{name: "trailing byte", data: "990290008e08000000000000000000"},
		{name: "trailing object", data: "990290008e08000000000000000099029000"},
		{name: "missing padding indicator", data: "871000000000000000000000000000000000990290008e080000000000000000"},
		{name: "invalid padding indicator", data: "87110000000000000000000000000000000000990290008e080000000000000000"},
		{name: "empty ciphertext", data: "870101990290008e080000000000000000"},
		{name: "nonblock ciphertext", data: "87020100990290008e080000000000000000"},
		{name: "truncated ciphertext", data: "8711010000"},
		{name: "indefinite length", data: "9980900000008e080000000000000000"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := newRecordSession(recordKeys(), iso7816.EncodingShort)
			before := session

			response, err := session.unprotect(iso7816.Response{Data: recordHex(t, test.data), Status: 0x9000}, [16]byte{1})
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("unprotect = %v, want invalid response", err)
			}

			if response.Data != nil || session != before {
				t.Error("malformed response released data or changed session state")
			}
		})
	}
}

func TestRecordAuthenticatesBeforeDecrypting(t *testing.T) {
	// This ciphertext decrypts to sixteen zero bytes: invalid ISO padding.
	// The record's R-MAC is independently calculated with OpenSSL.
	response := iso7816.Response{
		Data:   recordHex(t, "871101e05b19e6a8891af1fc1b4181202a150d990290008e088e052c6abdbb6044"),
		Status: 0x9000,
	}
	session := newRecordSession(recordKeys(), iso7816.EncodingShort)
	before := session

	_, err := session.unprotect(response, [16]byte{1})
	if !errors.Is(err, ErrInvalidResponse) || errors.Is(err, ErrAuthentication) {
		t.Errorf("authenticated invalid padding = %v", err)
	}

	response.Data[len(response.Data)-1] ^= 1

	_, err = session.unprotect(response, [16]byte{1})
	if !errors.Is(err, ErrAuthentication) || !errors.Is(err, ErrInvalidResponse) {
		t.Errorf("unauthenticated invalid padding = %v, want authentication failure", err)
	}

	if session != before {
		t.Error("rejected responses changed session state")
	}
}

func TestRecordRejectsReplayAndTampering(t *testing.T) {
	valid := recordHex(t, "872101ec0be757fe838d768f1362238a19a718761c2481b8a50d8924263c195fa87263990290008e08190ea8a6548b0e15")
	for _, position := range []int{3, 20, 38, len(valid) - 1} {
		session := newRecordSession(recordKeys(), iso7816.EncodingShort)
		data := bytes.Clone(valid)
		data[position] ^= 1

		response, err := session.unprotect(iso7816.Response{Data: data, Status: 0x9000}, [16]byte{})
		if !errors.Is(err, ErrAuthentication) || response.Data != nil {
			t.Errorf("tampering at %d = data %x, error %v", position, response.Data, err)
		}
	}

	session := newRecordSession(recordKeys(), iso7816.EncodingShort)

	response := iso7816.Response{Data: valid, Status: 0x9000}
	if _, err := session.unprotect(response, [16]byte{}); err != nil {
		t.Fatal(err)
	}

	before := session

	_, err := session.unprotect(response, [16]byte{})
	if !errors.Is(err, ErrAuthentication) || session != before {
		t.Errorf("response replay = %v; state changed = %v", err, session != before)
	}
}

func TestRecordAuthenticatesOriginalBEREncoding(t *testing.T) {
	session := newRecordSession(recordKeys(), iso7816.EncodingShort)
	// BER permits long-form lengths for small values. This MAC covers the
	// original 99 81 02 encoding, not a canonicalized 99 02 replacement.
	response, err := session.unprotect(iso7816.Response{
		Data:   recordHex(t, "99810290008e0863d76094b7ebd8ef"),
		Status: 0x9000,
	}, [16]byte{})
	if err != nil {
		t.Fatal(err)
	}

	if response.Status != 0x9000 || len(response.Data) != 0 {
		t.Errorf("unprotected BER response = %+v", response)
	}
}

func TestRecordRejectsOuterStatus(t *testing.T) {
	for _, status := range []iso7816.StatusWord{0x6882, 0x6982, 0x6987, 0x6988, 0x6a82, 0x6100} {
		session := newRecordSession(recordKeys(), iso7816.EncodingShort)

		_, err := session.unprotect(iso7816.Response{Status: status}, [16]byte{})
		if !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("outer status %s = %v", status, err)
		}

		var apduError *iso7816.APDUError
		if !errors.As(err, &apduError) || apduError.StatusWord() != status {
			t.Errorf("outer status %s lost APDU error: %v", status, err)
		}
	}
}

func TestRecordRejectsUnsupportedCommands(t *testing.T) {
	tests := []iso7816.Command{
		{CLA: 0x0c, INS: 0xcb},
		{CLA: 0x10, INS: 0xcb},
		{CLA: 0x80, INS: 0xcb},
		{INS: 0xa4},
		{INS: 0xc0},
		{INS: 0x87, P1: 0x2e, P2: 4},
		{INS: 0xcb, Le: 1},
		{INS: 0xcb, Le: 65536},
		{INS: 0xcb, Data: make([]byte, 65536)},
	}

	for _, command := range tests {
		session := newRecordSession(recordKeys(), iso7816.EncodingShort)
		before := session

		_, _, err := session.protect(command)
		if !errors.Is(err, iso7816.ErrInvalidCommand) {
			t.Errorf("protect CLA=%02x INS=%02x P2=%02x Le=%d data length=%d = %v", command.CLA, command.INS, command.P2, command.Le, len(command.Data), err)
		}

		if session != before {
			t.Error("unsupported command changed session state")
		}
	}
}

func TestRecordCounterExhaustionClearsKeys(t *testing.T) {
	session := newRecordSession(recordKeys(), iso7816.EncodingShort)
	for i := 1; i < len(session.counter); i++ {
		session.counter[i] = 0xff
	}

	_, next, err := session.protect(iso7816.Command{INS: 0x20, P2: 0x80})
	if err != nil {
		t.Fatal(err)
	}

	// No ciphertext is needed; authenticate a status-only response so the
	// final counter value can commit without an independent CBC vector.
	data := recordHex(t, "99029000")
	mac := cmac(session.keys.rmac[:], append(make([]byte, 16), data...))
	data = append(data, 0x8e, 8)
	data = append(data, mac[:8]...)

	if _, err := session.unprotect(iso7816.Response{Data: data, Status: 0x9000}, next); err != nil {
		t.Fatal(err)
	}

	if session.keys != (sessionKeys{}) || session.counter != [16]byte{} || session.commandChain != [16]byte{} || session.responseChain != [16]byte{} {
		t.Error("exhausted session retained keys or state")
	}

	if _, _, err := session.protect(iso7816.Command{INS: 0x20, P2: 0x80}); !errors.Is(err, ErrSessionExhausted) {
		t.Errorf("protect after counter exhaustion = %v", err)
	}
}
