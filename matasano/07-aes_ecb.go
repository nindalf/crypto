package matasano

import (
	"runtime"
	"sync"

	"github.com/nindalf/crypto/aes"
)

// DecryptAESECB decrypts a ciphertext encrypted with AES in ECB mode.
// This solves http://cryptopals.com/sets/1/challenges/7/
func DecryptAESECB(b, key []byte) {
	state := make([]uint32, len(b)/4)
	aes.Pack(state, b)

	expkey := aes.KeyExpansion(key)
	for i := 0; i < len(state); i += 4 {
		aes.DecryptAES(state[i:i+4], expkey)
	}

	aes.Unpack(b, state)
}

// EncryptAESECB encrypts a plaintext with AES in ECB mode.
func EncryptAESECB(b, key []byte) {
	state := make([]uint32, len(b)/4)
	aes.Pack(state, b)

	expkey := aes.KeyExpansion(key)
	for i := 0; i < len(state); i += 4 {
		aes.EncryptAES(state[i:i+4], expkey)
	}
	aes.Unpack(b, state)
}

// EncryptAESECBParallel encrypts a plaintext with AES in ECB mode.
func EncryptAESECBParallel(b, key []byte) {
	state := make([]uint32, len(b)/4)
	aes.Pack(state, b)

	expkey := aes.KeyExpansion(key)
	c := runtime.NumCPU()
	blocks := len(state) / 4
	blocksperCPU := blocks/c + 1
	var wg sync.WaitGroup
	for i := 0; i+4*blocksperCPU <= len(state); i += 4 * blocksperCPU {
		wg.Add(1)
		go encryptECBblocks(state[i:i+4*blocksperCPU], expkey, &wg)
	}
	wg.Wait()
	aes.Unpack(b, state)
}

func encryptECBblocks(state, expkey []uint32, wg *sync.WaitGroup) {
	for i := 0; i < len(state); i += 4 {
		aes.EncryptAES(state[i:i+4], expkey)
	}
	wg.Done()
}
