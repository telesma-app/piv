package sm

import "crypto/aes"

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
