package matasano

import (
	"crypto/cipher"

	"github.com/nindalf/crypto/aes"
)

var cbcDec = NewCBCDecrypter(aesBlockCipher, []byte{})
var cbcEnc = NewCBCEncrypter(aesBlockCipher, []byte{})

type cbc struct {
	cipher.Block // the block cipher
	iv           []byte
}

type ivSetter interface {
	SetIV([]byte)
}

// cbcDecrypter decrypts a ciphertext encrypted with AES in CBC mode.
// This solves http://cryptopals.com/sets/2/challenges/10/
type cbcDecrypter cbc

// NewCBCDecrypter creates a new CBC decrypter using a given block cipher
func NewCBCDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	ivcopy := make([]byte, aes.BlockSize)
	copy(ivcopy, iv)
	c := &cbc{b, ivcopy}
	return (*cbcDecrypter)(c)
}

func (c *cbcDecrypter) CryptBlocks(dst, src []byte) {
	temp1, temp2 := make([]byte, aes.BlockSize), make([]byte, aes.BlockSize)
	copy(temp1, c.iv)
	for len(src) > 0 && len(dst) > 0 {
		copy(temp2, src[:aes.BlockSize])

		c.Decrypt(dst[:aes.BlockSize], src[:aes.BlockSize])
		xorBytes(dst[:aes.BlockSize], temp1)

		src = src[aes.BlockSize:]
		dst = dst[aes.BlockSize:]

		copy(temp1, temp2)
	}
}

func (c *cbcDecrypter) SetIV(iv []byte) {
	copy(c.iv, iv)
}

// cbcDecrypter decrypts a ciphertext encrypted with AES in CBC mode.
// This solves http://cryptopals.com/sets/2/challenges/10/
type cbcEncrypter cbc

// NewCBCEncrypter creates a new CBC Encrypter using a given block cipher
func NewCBCEncrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	ivcopy := make([]byte, aes.BlockSize)
	copy(ivcopy, iv)
	c := &cbc{b, ivcopy}
	return (*cbcEncrypter)(c)
}

func (c *cbcEncrypter) CryptBlocks(dst, src []byte) {
	temp := make([]byte, aes.BlockSize)
	copy(temp, c.iv)

	for len(src) > 0 && len(dst) > 0 {
		xorBytes(temp, src)
		c.Encrypt(dst[:aes.BlockSize], temp)

		copy(temp, dst[:aes.BlockSize])

		src = src[aes.BlockSize:]
		dst = dst[aes.BlockSize:]
	}
}

func (c *cbcEncrypter) SetIV(iv []byte) {
	copy(c.iv, iv)
}

func xorBytes(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}
