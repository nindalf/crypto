package matasano

import "github.com/nindalf/crypto/aes"

// DecryptAESCTR decrypts a ciphertext encrypted with AES in CTR mode.
func DecryptAESCTR(b, key, iv []byte) {
	ctr(b, key, iv)
}

// EncryptAESCTR encrypts a plaintext with AES in CTR mode.
func EncryptAESCTR(b, key, iv []byte) {
	ctr(b, key, iv)
}

func ctr(b, key, ivc []byte) {
	aesc := aes.NewCipher(key)

	iv := make([]byte, len(ivc))
	copy(iv, ivc)
	ctr := fromBytes(iv)

	for i := 0; i < len(b); i += aes.BlockSize {
		ctr.ToBytes(iv)
		ctr.Add(1)

		aesc.Encrypt(iv, iv)

		for j := 0; j < aes.BlockSize && i+j < len(b); j++ {
			b[i+j] ^= iv[j]
		}
	}
}

// uint128 is an unsigned 128-bit integer
type uint128 struct {
	high uint64
	low  uint64
}

// Add adds a number to the uint128
func (u *uint128) Add(a uint64) {
	if u.low > u.low+a {
		// lower 64 bits overflowed
		u.high++
	}
	u.low = u.low + a
}

// ToBytes copies the value of the uint128 u to the first 16 bytes of result
func (u uint128) ToBytes(result []byte) {
	for i := uint64(0); i < 8; i++ {
		result[i] = byte(u.high >> (8 * (7 - i)))
		result[i+8] = byte(u.low >> (8 * (7 - i)))
	}
}

// fromBytes creates a uint128 from the input []byte of length 16
func fromBytes(in []byte) uint128 {
	high, low := uint64(0), uint64(0)
	for i := uint64(0); i < 8; i++ {
		high |= uint64(in[i]) << (8 * (7 - i))
		low |= uint64(in[i+8]) << (8 * (7 - i))
	}
	return uint128{high, low}
}
