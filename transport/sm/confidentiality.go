package sm

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// encrypt returns CBC ciphertext with ISO/IEC 9797-1 method 2 padding and the
// counter-derived IV required by SP 800-73-5 Part 2, Section 4.2.2.
func encrypt(key []byte, counter [16]byte, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	block.Encrypt(counter[:], counter[:])

	data := make([]byte, (len(plaintext)/aes.BlockSize+1)*aes.BlockSize)
	copy(data, plaintext)
	data[len(plaintext)] = 0x80
	cipher.NewCBCEncrypter(block, counter[:]).CryptBlocks(data, data)

	return data
}

// decrypt is called only after the record MAC has been verified. The returned
// plaintext owns its buffer; malformed peer ciphertext or padding is rejected.
func decrypt(key []byte, counter [16]byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("%w: invalid encrypted data length", ErrInvalidResponse)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	block.Encrypt(counter[:], counter[:])

	data := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, counter[:]).CryptBlocks(data, ciphertext)

	for i := len(data) - 1; i >= len(data)-aes.BlockSize; i-- {
		if data[i] == 0x80 {
			clear(data[i:])
			return data[:i:i], nil
		}

		if data[i] != 0 {
			break
		}
	}

	clear(data)

	return nil, fmt.Errorf("%w: invalid encrypted data padding", ErrInvalidResponse)
}
