package matasano

import (
	"fmt"
	"math/rand"
	"time"
)

// DecryptAESCTR decrypts a ciphertext encrypted with AES in CTR mode.
// This code does not work for ciphertexts longer than 2^32 blocks
func DecryptAESCTR(b, key []byte, iv []uint32) {
	state := make([]uint32, len(b)/4)
	pack(b, state)
	fmt.Printf("%x - %x\n", b[len(b)-16:len(b)], state[len(state)-4:len(state)])

	expkey := keyExpansion(key)
	t := []uint32{0, 0, 0, 0}
	copy(t, iv)
	ctr := uint32(0)
	for i := 0; i < len(state); i += 4 {
		iv[3] ^= ctr
		ctr++
		encryptAES(iv, expkey)
		for j := 0; j < 4 && i+j < len(state); j++ {
			state[i+j] ^= iv[j]
		}
		copy(iv, t)
	}

	unpack(b, state)
}

// EncryptAESCTR encrypts a plaintext with AES in CTR mode.
// This code does not work for plaintexts longer than 2^32 blocks
func EncryptAESCTR(b, key []byte) []uint32 {
	state := make([]uint32, len(b)/4)
	pack(b, state)

	expkey := keyExpansion(key)

	rand.Seed(time.Now().UnixNano())
	iv := []uint32{rand.Uint32(), rand.Uint32(), rand.Uint32(), rand.Uint32()}
	t := []uint32{0, 0, 0, 0}
	copy(t, iv)
	ctr := uint32(0)
	for i := 0; i < len(state); i += 4 {
		iv[3] ^= ctr
		ctr++
		encryptAES(iv, expkey)
		for j := 0; j < 4; j++ {
			state[i+j] ^= iv[j]
		}
		copy(iv, t)
	}

	unpack(b, state)
	return t
}
