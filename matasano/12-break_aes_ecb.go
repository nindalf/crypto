package matasano

import (
	"bytes"

	"github.com/nindalf/crypto/aes"
)

// Used when a random key needs to be used repeatedly
var rkey = randbytes(16)

//  a function that produces: AES-128-ECB(b || unknown-string, random-key)
func oracleeasy(b []byte) []byte {
	plaintext := []byte("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	dec := make([]byte, (3*len(plaintext))/4)
	DecodeBase64(dec, plaintext)
	b = append(b, dec...)
	b = PadPKCS7(b, aes.BlockSize)
	EncryptAESECB(b, rkey)
	return b
}

// BreakECBEasy decrypts a ciphertext received from the oracle function (defined above)
// It does so by repeated calls to the oracle
// This solves http://cryptopals.com/sets/2/challenges/12/
func BreakECBEasy() []byte {
	chosens := genChosenCiphersEasy()
	var decrypted bytes.Buffer
	previous := make([]byte, aes.BlockSize, len(chosens[0]))
	for i := 0; i < len(chosens[0]); i += aes.BlockSize {
		previous = decrypt16bytesEasy(chosens, previous, i)
		decrypted.Write(previous)
	}
	return decrypted.Bytes()
}

func decrypt16bytesEasy(chosens [][]byte, previous []byte, index int) []byte {
	decrypted := make([]byte, 0, aes.BlockSize)
	for i := len(chosens) - 1; i >= 0; i-- {
		previous = previous[1:len(previous)]
		dec := decryptbyteEasy(chosens[i][index:index+aes.BlockSize], previous)
		previous = append(previous, dec)
		decrypted = append(decrypted, dec)
	}
	return decrypted
}

func decryptbyteEasy(chosen, previous []byte) byte {
	previous = append(previous, byte(0))
	for i := 0; i < 255; i++ {
		previous[aes.BlockSize-1] = byte(i)
		if bytes.Equal(oracleeasy(previous)[0:aes.BlockSize], chosen) {
			return byte(i)
		}
	}
	return 0
}

func genChosenCiphersEasy() [][]byte {
	chosens := make([][]byte, 0, aes.BlockSize)
	prefix := make([]byte, 0, aes.BlockSize-1)
	chosens = append(chosens, oracleeasy(prefix))
	var x byte
	for i := 0; i < aes.BlockSize-1; i++ {
		prefix = append(prefix, x)
		chosens = append(chosens, oracleeasy(prefix))
	}
	return chosens
}
