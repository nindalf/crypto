package matasano

import (
	"math/rand"
	"time"
)

// OracleAES guesses whether a ciphertext has been encrypted with ECB mode (1) or not (0)
// This only works if the plaintext contains either
// 1. 2 or more identical 32-byte blocks of the same character
// 2. 2 or more identical 32-byte blocks of any characters *but* separated by 16*n bytes (n=0,1,2,3...)
// The test file contains an example of both
// This solves http://cryptopals.com/sets/2/challenges/10/
func OracleAES(ciphers [][]byte) []int {
	guesses := make([]int, len(ciphers))
	for i := range ciphers {
		if isAESECB(ciphers[i]) {
			guesses[i] = 1
		} else {
			guesses[i] = 0
		}
	}
	return guesses
}

func isAESECB(b []byte) bool {
	if similarBlocks(string(b)) > 0 {
		return true
	}
	return false
}

// generateCiphertexts accepts a plaintext b and generates ciphertexts based on this procedure
// 1. Prefixes 5-20 random bytes
// 2. Appends PKCS#7 padding
// 3. Generates a random 16-byte key to encrypt it with
// 4. Encrypts with the plaintext AES-ECB or AES-CBC, depending on the flip of a coin (rand.Intn(2))
// All ciphertexts and the result of each coin flip is returned
func generateCiphertexts(b []byte) ([][]byte, []int) {
	rand.Seed(time.Now().UnixNano())

	ciphers := make([][]byte, 10)
	coinflips := make([]int, 10)
	for i := range ciphers {
		p := getPlaintext(b)
		key := randbytes(16)
		coin := rand.Intn(2)
		if coin == 1 {
			EncryptAESECB(p, key)
		} else {
			EncryptAESCBC(p, key)
		}
		ciphers[i] = p
		coinflips[i] = coin
	}
	return ciphers, coinflips
}

// prepends 5-20 random bytes and appends pkcs#7 padding
func getPlaintext(b []byte) []byte {
	prefix := randbytes(rand.Intn(16) + 5)
	p := make([]byte, len(prefix), len(b)+20)
	copy(p, prefix)
	p = append(p, b...)
	p = padPKCS7(p, 16)
	return p
}

// randbytes generates an byte slice of length n, filled with random bytes
// n should be greater than 3
func randbytes(n int) []byte {
	pad := n - (n % 4)
	b := make([]byte, n+pad)
	if n < 4 {
		return b
	}
	for i := 0; i < n; i += 4 {
		r := rand.Uint32()
		b[i] = byte(r >> 24)
		b[i+1] = byte(r >> 16 & 0xff)
		b[i+2] = byte(r >> 8 & 0xff)
		b[i+3] = byte(r & 0xff)
	}
	return b[0:n]
}
