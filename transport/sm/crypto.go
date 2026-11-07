package sm

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

type sessionKeys struct {
	keySize int
	cfrm    [32]byte
	mac     [32]byte
	enc     [32]byte
	rmac    [32]byte
}

func (k *sessionKeys) clear() {
	clear(k.cfrm[:])
	clear(k.mac[:])
	clear(k.enc[:])
	clear(k.rmac[:])
	k.keySize = 0
}

// deriveKeys implements SP 800-73-5 Part 2, Section 4.1.6. Public-key
// coordinates in OtherInfo exclude the SEC1 uncompressed-point prefix.
func deriveKeys(suite cipherSuite, z []byte, hostID, cardID [8]byte, hostPublic, nonce []byte) sessionKeys {
	otherInfo := make([]byte, 0, 78)
	otherInfo = append(otherInfo, 4, suite.kdfAlgorithm, suite.kdfAlgorithm, suite.kdfAlgorithm, suite.kdfAlgorithm, 8)
	otherInfo = append(otherInfo, hostID[:]...)
	otherInfo = append(otherInfo, 1, 0, 0x10)
	otherInfo = append(otherInfo, hostPublic[1:17]...)
	otherInfo = append(otherInfo, 8)
	otherInfo = append(otherInfo, cardID[:]...)
	otherInfo = append(otherInfo, byte(suite.nonceSize))
	otherInfo = append(otherInfo, nonce...)
	otherInfo = append(otherInfo, 1, 0)

	var material [144]byte
	defer clear(material[:])

	h := suite.newHash()
	for offset, i := 0, uint32(1); offset < 4*suite.keySize; offset, i = offset+h.Size(), i+1 {
		h.Reset()

		var counter [4]byte
		binary.BigEndian.PutUint32(counter[:], i)
		h.Write(counter[:])
		h.Write(z)
		h.Write(otherInfo)
		h.Sum(material[offset:offset])
	}

	keys := sessionKeys{keySize: suite.keySize}
	copy(keys.cfrm[:suite.keySize], material[:suite.keySize])
	copy(keys.mac[:suite.keySize], material[suite.keySize:2*suite.keySize])
	copy(keys.enc[:suite.keySize], material[2*suite.keySize:3*suite.keySize])
	copy(keys.rmac[:suite.keySize], material[3*suite.keySize:4*suite.keySize])

	return keys
}

// cmac implements AES-CMAC as specified by SP 800-38B, Section 6.1.
func cmac(key, data []byte) [16]byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	var first, second [16]byte
	block.Encrypt(first[:], first[:])
	doubleBlock(&first)
	second = first
	doubleBlock(&second)

	var result [16]byte
	for len(data) > aes.BlockSize {
		for i := range result {
			result[i] ^= data[i]
		}

		block.Encrypt(result[:], result[:])

		data = data[aes.BlockSize:]
	}

	last := second
	if len(data) == aes.BlockSize {
		last = first
	} else {
		last[len(data)] ^= 0x80
	}

	for i, b := range data {
		last[i] ^= b
	}

	for i := range result {
		result[i] ^= last[i]
	}

	block.Encrypt(result[:], result[:])
	clear(first[:])
	clear(second[:])
	clear(last[:])

	return result
}

func doubleBlock(block *[16]byte) {
	carry := block[0] >> 7
	for i := range len(block) - 1 {
		block[i] = block[i]<<1 | block[i+1]>>7
	}

	block[15] = block[15]<<1 ^ (0x87 * carry)
}

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
