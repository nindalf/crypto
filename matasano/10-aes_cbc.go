package matasano

import "github.com/nindalf/crypto/aes"

// DecryptAESCBC decrypts a ciphertext encrypted with AES in CBC mode.
// This solves http://cryptopals.com/sets/2/challenges/10/
func DecryptAESCBC(b, key, iv []byte) {
	aesc := aes.NewCipher(key)

	t := make([]byte, aes.BlockSize)
	for i := 0; i < len(b); i += aes.BlockSize {
		copy(t, b[i:i+aes.BlockSize])
		aesc.Decrypt(b[i:i+aes.BlockSize], b[i:i+aes.BlockSize])
		for j := range b[i : i+aes.BlockSize] {
			b[i+j] ^= iv[j]
		}
		copy(iv, t)
	}
}

// EncryptAESCBC encrypts a plaintext with AES in CBC mode.
func EncryptAESCBC(b, key, iv []byte) {
	aesc := aes.NewCipher(key)

	for i := 0; i < len(b); i += aes.BlockSize {
		for j := range b[i : i+aes.BlockSize] {
			b[i+j] ^= iv[j]
		}
		aesc.Encrypt(b[i:i+aes.BlockSize], b[i:i+aes.BlockSize])
		iv = b[i : i+aes.BlockSize]
	}
}
