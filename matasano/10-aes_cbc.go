package matasano

import "crypto/rand"

// DecryptAESCBC decrypts a ciphertext encrypted with AES in CBC mode.
// This solves http://cryptopals.com/sets/2/challenges/10/
func DecryptAESCBC(b, key []byte, iv []uint32) {
	state := make([]uint32, len(b)/4)
	pack(state, b)

	expkey := keyExpansion(key)
	t := []uint32{0, 0, 0, 0}
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

// EncryptAESCBC encrypts a plaintext with AES in CBC mode.
func EncryptAESCBC(b, key []byte) []uint32 {
	state := make([]uint32, len(b)/4)
	pack(state, b)

	expkey := keyExpansion(key)

	iv, ivcopy := []uint32{0, 0, 0, 0}, []uint32{0, 0, 0, 0}
	r := make([]byte, 16)
	_, err := rand.Read(r)
	if err != nil {
		return iv
	}
	pack(iv, r)
	copy(ivcopy, iv)

	for i := 0; i < len(state); i += 4 {
		for j := 0; j < 4; j++ {
			state[i+j] ^= iv[j]
		}
		encryptAES(state[i:i+4], expkey)
		iv = state[i : i+4]
	}

	unpack(b, state)
	return ivcopy
}
