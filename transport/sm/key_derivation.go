package sm

import "encoding/binary"

type sessionKeys struct {
	keySize int
	cfrm    [32]byte
	mac     [32]byte
	enc     [32]byte
	rmac    [32]byte
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

func (k *sessionKeys) clear() {
	clear(k.cfrm[:])
	clear(k.mac[:])
	clear(k.enc[:])
	clear(k.rmac[:])
	k.keySize = 0
}
