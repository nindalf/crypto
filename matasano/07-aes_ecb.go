package matasano

import (
	"crypto/cipher"
	"runtime"
	"sync"

	"github.com/nindalf/crypto/aes"
)

// Used when a random key needs to be used repeatedly
var rkey = randbytes(16)
var aesBlockCipher = aes.NewCipher(rkey)
var ecbDec = newECBDecrypter(aesBlockCipher)
var ecbEnc = newECBEncrypter(aesBlockCipher)

type ecb struct {
	cipher.Block // the block cipher
}

// ecbDecrypter decrypts a ciphertext encrypted with AES in ECB mode.
// implements the BlockMode interface from crypto/cipher
// http://golang.org/pkg/crypto/cipher/#BlockMode
// This solves http://cryptopals.com/sets/1/challenges/7/
type ecbDecrypter ecb

func newECBDecrypter(b cipher.Block) cipher.BlockMode {
	e := &ecb{b}
	return (*ecbDecrypter)(e)
}

func (e *ecbDecrypter) CryptBlocks(dst, src []byte) {
	for len(src) > 0 && len(dst) > 0 {
		e.Decrypt(dst[:aes.BlockSize], src[:aes.BlockSize])
		src = src[aes.BlockSize:]
		dst = dst[aes.BlockSize:]
	}
}

// ecbEncrypter encrypts a plaintext with AES in ECB mode.
// implements the BlockMode interface from crypto/cipher
// http://golang.org/pkg/crypto/cipher/#BlockMode
type ecbEncrypter ecb

func newECBEncrypter(b cipher.Block) cipher.BlockMode {
	e := &ecb{b}
	return (*ecbEncrypter)(e)
}

func (e *ecbEncrypter) CryptBlocks(dst, src []byte) {
	for len(src) > 0 && len(dst) > 0 {
		e.Encrypt(dst[:aes.BlockSize], src[:aes.BlockSize])
		src = src[aes.BlockSize:]
		dst = dst[aes.BlockSize:]
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
	for len(b) > 0 {
		aesc.Decrypt(b[:aes.BlockSize], b[:aes.BlockSize])
		b = b[aes.BlockSize:]
	}
	wg.Done()
}
