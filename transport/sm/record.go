package sm

import (
	"crypto/subtle"
	"fmt"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
)

// recordSession protects complete logical APDUs. Its owner serializes access;
// fragmentation and GET RESPONSE happen after protect and before unprotect.
type recordSession struct {
	keys          sessionKeys
	commandChain  [16]byte
	responseChain [16]byte
	counter       [16]byte
	encoding      iso7816.Encoding
}

func newRecordSession(keys sessionKeys, encoding iso7816.Encoding) recordSession {
	return recordSession{keys: keys, counter: [16]byte{15: 1}, encoding: encoding}
}

// protect leaves state unchanged until an authenticated response commits it.
// This permits reuse when cancellation prevents the first transmission.
func (s *recordSession) protect(command iso7816.Command) (iso7816.Command, [16]byte, error) {
	if s.counter == [16]byte{} {
		return iso7816.Command{}, [16]byte{}, ErrSessionExhausted
	}

	if command.CLA != 0 {
		return iso7816.Command{}, [16]byte{}, fmt.Errorf("%w: unsupported PIV SM CLA %02x", iso7816.ErrInvalidCommand, command.CLA)
	}

	// SP 800-73pt2-5, section 4.2, defines secure messaging for these commands.
	switch command.INS {
	case 0xcb, 0x20, 0x24, 0x87:
	default:
		return iso7816.Command{}, [16]byte{}, fmt.Errorf("%w: unsupported PIV SM instruction %02x", iso7816.ErrInvalidCommand, command.INS)
	}

	if command.INS == 0x87 && command.P2 == 0x04 {
		return iso7816.Command{}, [16]byte{}, fmt.Errorf("%w: PIV SM rekey requires a new session", iso7816.ErrInvalidCommand)
	}

	if command.Le != 0 && command.Le != 256 {
		return iso7816.Command{}, [16]byte{}, fmt.Errorf("%w: PIV SM Le must be absent or 256", iso7816.ErrInvalidCommand)
	}

	if len(command.Data) > 65535 {
		return iso7816.Command{}, [16]byte{}, fmt.Errorf("%w: PIV SM command data exceeds 65535 bytes", iso7816.ErrInvalidCommand)
	}

	var data []byte

	if len(command.Data) != 0 {
		encrypted := encrypt(s.keys.enc[:s.keys.keySize], s.counter, command.Data)
		data = bertlv.Append(data, 0x87, append([]byte{1}, encrypted...))
	}

	if command.Le != 0 {
		data = append(data, 0x97, 1, 0)
	}

	// NIST sections 4.2.3-4.2.4: Lc is excluded; the complete header is
	// padded to one AES block and always uses CLA 0C, before fragmentation.
	macInput := append([]byte(nil), s.commandChain[:]...)
	macInput = append(macInput, 0x0c, command.INS, command.P1, command.P2, 0x80)
	macInput = append(macInput, make([]byte, 11)...)
	macInput = append(macInput, data...)
	next := cmac(s.keys.mac[:s.keys.keySize], macInput)
	data = bertlv.Append(data, 0x8e, next[:8])

	if s.encoding == iso7816.EncodingExtended && len(data) > 65535 {
		return iso7816.Command{}, [16]byte{}, fmt.Errorf("%w: protected PIV SM command exceeds extended APDU limit", iso7816.ErrInvalidCommand)
	}

	command.CLA = 0x0c
	command.Data = data
	command.Le = 256
	command.Encoding = s.encoding

	return command, next, nil
}

// unprotect verifies the complete response before releasing any plaintext.
// The status in DO99 is authenticated application status and can be an error;
// an outer status other than 9000 is a fatal secure messaging failure.
func (s *recordSession) unprotect(response iso7816.Response, next [16]byte) (iso7816.Response, error) {
	if err := response.APDUError(); err != nil {
		return iso7816.Response{}, fmt.Errorf("%w: PIV SM processing failed: %w", ErrInvalidResponse, err)
	}

	encrypted, status, authenticated, mac, err := parseProtectedResponse(response.Data)
	if err != nil {
		return iso7816.Response{}, err
	}

	macInput := append([]byte(nil), s.responseChain[:]...)
	macInput = append(macInput, authenticated...)
	expected := cmac(s.keys.rmac[:s.keys.keySize], macInput)

	if subtle.ConstantTimeCompare(expected[:8], mac) != 1 {
		return iso7816.Response{}, fmt.Errorf("%w: invalid PIV SM response MAC: %w", ErrInvalidResponse, ErrAuthentication)
	}

	var plaintext []byte

	if encrypted != nil {
		counter := s.counter
		counter[0] = 0x80

		plaintext, err = decrypt(s.keys.enc[:s.keys.keySize], counter, encrypted)
		if err != nil {
			return iso7816.Response{}, err
		}
	}

	s.commandChain = next
	s.responseChain = expected

	// The most significant counter byte is reserved for response direction.
	// Exhausting the remaining 120 bits must never reuse an encryption IV.
	for i := len(s.counter) - 1; i > 0; i-- {
		s.counter[i]++
		if s.counter[i] != 0 {
			break
		}
	}

	if s.counter == [16]byte{} {
		s.clear()
	}

	return iso7816.Response{Data: plaintext, Status: status}, nil
}

// parseProtectedResponse recognizes exactly [DO87] DO99 DO8E in that order.
// authenticated borrows the original wire encoding; re-encoding TLVs would
// authenticate different bytes for valid BER length encodings.
func parseProtectedResponse(data []byte) (encrypted []byte, status iso7816.StatusWord, authenticated, mac []byte, err error) {
	original := data

	tag, value, rest, err := bertlv.Parse(data)
	if err != nil {
		return nil, 0, nil, nil, fmt.Errorf("%w: malformed PIV SM response: %w", ErrInvalidResponse, err)
	}

	if tag == 0x87 {
		if len(value) < 17 || value[0] != 1 || (len(value)-1)%16 != 0 {
			return nil, 0, nil, nil, fmt.Errorf("%w: invalid PIV SM encrypted data object", ErrInvalidResponse)
		}

		encrypted = value[1:]
		data = rest

		tag, value, rest, err = bertlv.Parse(data)
		if err != nil {
			return nil, 0, nil, nil, fmt.Errorf("%w: missing PIV SM status: %w", ErrInvalidResponse, err)
		}
	}

	if tag != 0x99 || len(value) != 2 {
		return nil, 0, nil, nil, fmt.Errorf("%w: invalid PIV SM status object", ErrInvalidResponse)
	}

	status = iso7816.NewStatusWord(value[0], value[1])
	authenticated = original[:len(original)-len(rest)]

	tag, value, rest, err = bertlv.Parse(rest)
	if err != nil {
		return nil, 0, nil, nil, fmt.Errorf("%w: missing PIV SM response MAC: %w", ErrInvalidResponse, err)
	}

	if tag != 0x8e || len(value) != 8 || len(rest) != 0 {
		return nil, 0, nil, nil, fmt.Errorf("%w: invalid PIV SM response MAC object", ErrInvalidResponse)
	}

	return encrypted, status, authenticated, value, nil
}

func (s *recordSession) clear() {
	s.keys.clear()
	clear(s.commandChain[:])
	clear(s.responseChain[:])
	clear(s.counter[:])
}
