package matasano

import (
	"crypto/cipher"

	"github.com/nindalf/crypto/aes"
)

var ctrEncDec = newCTR(aesBlockCipher, make([]byte, aes.BlockSize))

// ctr implements the Stream interface from crypto/cipher
// http://golang.org/pkg/crypto/cipher/#Stream
type ctr struct {
	block   cipher.Block
	counter byteint
	temp    []byte
}

func newCTR(block cipher.Block, iv []byte) cipher.Stream {
	counter := make(byteint, aes.BlockSize)
	copy(counter, iv)
	temp := make([]byte, aes.BlockSize)
	return ctr{block, counter, temp}
}

// XORKeyStream XORs each byte in the given slice with a byte from the
// cipher's key stream. Dst and src may point to the same memory.
// If len(dst) < len(src), XORKeyStream should panic. It is acceptable
// to pass a dst bigger than src, and in that case, XORKeyStream will
// only update dst[:len(src)] and will not touch the rest of dst.
func (c ctr) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("dst smaller than src")
	}

	for len(src) > 0 {
		copy(c.temp, c.counter)
		c.counter.AddOne()

		c.block.Encrypt(c.temp, c.temp)

		l := min(len(src), aes.BlockSize)
		xorBytes(c.temp[:l], src[:l])
		copy(dst[:l], c.temp)

		dst = dst[l:]
		src = src[l:]
	}
}

func (c ctr) SetIV(iv []byte) {
	copy(c.counter, iv)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// byteint is n-byte integer
// It supports one operation - AddOne
type byteint []byte

func (b byteint) AddOne() {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			break
		}
	}
}
