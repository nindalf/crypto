package matasano

import "crypto/rand"

// DecryptAESCTR decrypts a ciphertext encrypted with AES in CTR mode.
// This code does not work for ciphertexts longer than 2^32 blocks
func DecryptAESCTR(b, key []byte, iv []uint32) {
	ctr(b, key, iv)
}

// EncryptAESCTR encrypts a plaintext with AES in CTR mode.
// This code does not work for plaintexts longer than 2^32 blocks
func EncryptAESCTR(b, key []byte) []uint32 {
	iv, ivcopy := []uint32{0, 0, 0, 0}, []uint32{0, 0, 0, 0}
	r := make([]byte, 16)
	_, err := rand.Read(r)
	if err != nil {
		return iv
	}
	pack(iv, r)
	copy(ivcopy, iv)

	ctr(b, key, iv)

	return ivcopy
}

func ctr(b, key []byte, iv []uint32) {
	expkey := keyExpansion(key)

	ivcopy := []uint32{0, 0, 0, 0}
	copy(ivcopy, iv)

	ivbytes := make([]byte, bsize)
	ctr := uint32(0)

	for i := 0; i < len(b); i += bsize {
		iv[3] ^= ctr
		ctr++
		encryptAES(iv, expkey)
		unpack(ivbytes, iv)

		for j := 0; j < bsize && i+j < len(b); j++ {
			b[i+j] ^= ivbytes[j]
		}
		copy(iv, ivcopy)
	}
}
