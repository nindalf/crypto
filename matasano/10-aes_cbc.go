package matasano

import (
	"math/rand"
	"time"
)

// DecryptAESCBC decrypts a ciphertext encrypted with AES in CBC mode.
// This solves http://cryptopals.com/sets/2/challenges/10/
func DecryptAESCBC(b, key []byte, iv []uint32) {
	state := make([]uint32, len(b)/4)
	pack(b, state)

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

// EncryptAESCBC encrypts a plaintext with AES in ECB mode.
func EncryptAESCBC(b, key []byte) []uint32 {
	state := make([]uint32, len(b)/4)
	pack(b, state)

	expkey := keyExpansion(key)

	rand.Seed(time.Now().UnixNano())
	iv := []uint32{rand.Uint32(), rand.Uint32(), rand.Uint32(), rand.Uint32()}
	c := make([]uint32, 4)
	copy(c, iv)

	for i := 0; i < len(state); i += 4 {
		for j := 0; j < 4; j++ {
			state[i+j] ^= iv[j]
		}
		encryptAES(state[i:i+4], expkey)
		iv = state[i : i+4]
	}

	unpack(b, state)
	return c
}
