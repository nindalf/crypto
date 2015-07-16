package matasano

// DecryptAESCBC decrypts a ciphertext encrypted with AES in CBC mode.
// This solves http://cryptopals.com/sets/2/challenges/10/
func DecryptAESCBC(b, key []byte) {
	state := make([]uint32, len(b)/4)
	pack(b, state)

	expkey := keyExpansion(key)
	iv, t := []uint32{0, 0, 0, 0}, []uint32{0, 0, 0, 0}
	for i := 0; i < len(state); i += 4 {
		copy(t, state[i:i+4])
		decryptAES(state[i:i+4], expkey)
		for j := 0; j < 4; j++ {
			state[i+j] ^= iv[j]
		}
		copy(iv, t)
	}

	unpack(b, state)
}

// EncryptAESCBC encrypts a plaintext with AES in ECB mode.
func EncryptAESCBC(b, key []byte) {
	state := make([]uint32, len(b)/4)
	pack(b, state)

	expkey := keyExpansion(key)
	iv := []uint32{0, 0, 0, 0}
	for i := 0; i < len(state); i += 4 {
		for j := 0; j < 4; j++ {
			state[i+j] ^= iv[j]
		}
		encryptAES(state[i:i+4], expkey)
		iv = state[i : i+4]
	}

	unpack(b, state)
}
