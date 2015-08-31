package matasano

import (
	"runtime"
	"sync"
)

// DecryptAESECB decrypts a ciphertext encrypted with AES in ECB mode.
// This solves http://cryptopals.com/sets/1/challenges/7/
func DecryptAESECB(b, key []byte) {
	state := make([]uint32, len(b)/4)
	pack(state, b)

	expkey := keyExpansion(key)
	for i := 0; i < len(state); i += 4 {
		decryptAES(state[i:i+4], expkey)
	}

	unpack(b, state)
}

// EncryptAESECB encrypts a plaintext with AES in ECB mode.
func EncryptAESECB(b, key []byte) {
	state := make([]uint32, len(b)/4)
	pack(state, b)

	expkey := keyExpansion(key)
	for i := 0; i < len(state); i += 4 {
		encryptAES(state[i:i+4], expkey)
	}
	unpack(b, state)
}

// EncryptAESECBParallel encrypts a plaintext with AES in ECB mode.
func EncryptAESECBParallel(b, key []byte) {
	state := make([]uint32, len(b)/4)
	pack(state, b)

	expkey := keyExpansion(key)
	c := runtime.NumCPU()
	blocks := len(state) / 4
	blocksperCPU := blocks/c + 1
	var wg sync.WaitGroup
	for i := 0; i+4*blocksperCPU <= len(state); i += 4 * blocksperCPU {
		wg.Add(1)
		go encryptECBblocks(state[i:i+4*blocksperCPU], expkey, &wg)
	}
	wg.Wait()
	unpack(b, state)
}

func encryptECBblocks(state, expkey []uint32, wg *sync.WaitGroup) {
	for i := 0; i < len(state); i += 4 {
		encryptAES(state[i:i+4], expkey)
	}
	wg.Done()
}
