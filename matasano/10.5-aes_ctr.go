package matasano

import (
	"crypto/rand"

	"github.com/nindalf/crypto/aes"
)

// DecryptAESCTR decrypts a ciphertext encrypted with AES in CTR mode.
func DecryptAESCTR(b, key []byte, iv []uint32) {
	ctr(b, key, iv)
}

// EncryptAESCTR encrypts a plaintext with AES in CTR mode.
func EncryptAESCTR(b, key []byte) []uint32 {
	r := make([]byte, 16)
	_, err := rand.Read(r)
	if err != nil {
		return []uint32{}
	}

	iv, ivcopy := []uint32{0, 0, 0, 0}, []uint32{0, 0, 0, 0}
	aes.Pack(iv, r)
	copy(ivcopy, iv)

	ctr(b, key, iv)

	return ivcopy
}

func ctr(b, key []byte, iv []uint32) {
	expkey := aes.KeyExpansion(key)

	ivbytes := make([]byte, bsize)
	ctr := fromUint32(iv)

	for i := 0; i < len(b); i += bsize {
		ctr.ToUint32(iv)
		ctr.Add(1)

		aes.EncryptAES(iv, expkey)
		aes.Unpack(ivbytes, iv)

		for j := 0; j < bsize && i+j < len(b); j++ {
			b[i+j] ^= ivbytes[j]
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

// ToUint32 assigns the value of the uint128 to the []uint32 passed as a parameter
func (u uint128) ToUint32(result []uint32) {
	result[0] = uint32(u.high >> 32)
	result[1] = uint32(u.high)
	result[2] = uint32(u.low >> 32)
	result[3] = uint32(u.low)
}

// fromUint32 creates a uint128 from 4 uint32s
func fromUint32(in []uint32) uint128 {
	high := uint64(in[0])<<32 | uint64(in[1])
	low := uint64(in[2])<<32 | uint64(in[3])
	return uint128{high, low}
}
