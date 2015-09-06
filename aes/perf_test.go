package aes

import (
	"crypto/aes"
	"crypto/rand"
	"testing"
)

var (
	key  = make([]byte, aes.BlockSize)
	buf1 = make([]byte, aes.BlockSize)
	buf2 = make([]byte, aes.BlockSize)
)

// All benchmarks run on an Early-2013 Macbook Pro
// CPU Core i5-3230M. Supports AES-NI instructions
// RAM 8GB

// Using same/separate buffers changes the time taken
// Same buffer      - 30ns/op
// Different buffer - 27ns/op
func BenchmarkAssemblyAESSame(b *testing.B) {
	rand.Read(key)
	c, _ := aes.NewCipher(key)
	testFunc(b, c.Encrypt, buf1, buf1)
}

func BenchmarkAssemblyAESDifferent(b *testing.B) {
	rand.Read(key)
	c, _ := aes.NewCipher(key)
	testFunc(b, c.Encrypt, buf1, buf2)
}

// Using same/separate buffers does not change the time taken
// Takes             1200 ns/op
func BenchmarkMyAES(b *testing.B) {
	rand.Read(key)
	c := NewCipher(key)
	testFunc(b, c.Encrypt, buf1, buf2)
}

func testFunc(b *testing.B, f func([]byte, []byte), buf1, buf2 []byte) {
	for n := 0; n < b.N; n++ {
		f(buf1, buf2)
	}
}
