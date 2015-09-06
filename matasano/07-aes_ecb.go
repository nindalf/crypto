package matasano

import (
	"crypto/cipher"
	"runtime"
	"sync"

	"github.com/nindalf/crypto/aes"
)

// DecryptAESECB decrypts a ciphertext encrypted with AES in ECB mode.
// This solves http://cryptopals.com/sets/1/challenges/7/
func DecryptAESECB(b, key []byte) {
	aesc := aes.NewCipher(key)
	for i := 0; i < len(b); i += aes.BlockSize {
		aesc.Decrypt(b[i:i+aes.BlockSize], b[i:i+aes.BlockSize])
	}
}

// EncryptAESECB encrypts a plaintext with AES in ECB mode.
func EncryptAESECB(b, key []byte) {
	aesc := aes.NewCipher(key)
	for i := 0; i < len(b); i += aes.BlockSize {
		aesc.Encrypt(b[i:i+aes.BlockSize], b[i:i+aes.BlockSize])
	}
}

// EncryptAESECBParallel encrypts a plaintext with AES in ECB mode.
func EncryptAESECBParallel(b, key []byte) {
	aesc := aes.NewCipher(key)

	c := runtime.NumCPU()
	blocks := len(b) / aes.BlockSize
	blocksperCPU := blocks/c + 1
	var wg sync.WaitGroup

	for i := 0; i+aes.BlockSize*blocksperCPU <= len(b); i += aes.BlockSize * blocksperCPU {
		wg.Add(1)
		go encryptECBblocks(b[i:i+aes.BlockSize*blocksperCPU], aesc, &wg)
	}
	wg.Wait()
}

func encryptECBblocks(b []byte, aesc cipher.Block, wg *sync.WaitGroup) {
	for i := 0; i < len(b); i += aes.BlockSize {
		aesc.Encrypt(b[i:i+aes.BlockSize], b[i:i+aes.BlockSize])
	}
	wg.Done()
}
