package matasano

import (
	"bytes"
	"math/rand"

	"github.com/nindalf/crypto/aes"
)

var numBytes = rand.Intn(40)

//  a function that produces: AES-128-ECB(random-text-of-fixed-length || b || unknown-string, random-key)
func oraclemoderate(b []byte) []byte {
	plaintext := []byte("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	dec := make([]byte, (3*len(plaintext))/4)
	DecodeBase64(dec, plaintext)
	r := randbytes(numBytes)
	r = append(r, b...)
	r = append(r, dec...)
	r = PadPKCS7(r, aes.BlockSize)
	ecbEnc.CryptBlocks(r, r)
	return r
}

var oraclehelper func([]byte) []byte

func setupHelper() {
	var frontpad, cutblock int
	b := make([]byte, 64, 79)
	e := oraclemoderate(b)
	for similarBlocks(string(e)) < 4 {
		b = append(b, byte(0))
		e = oraclemoderate(b)
		frontpad++
	}
	s := string(e)
	for i := 0; i < len(s)-64; i += aes.BlockSize {
		// aes.BlockSize = 16
		if s[i:i+16] == s[i+16:i+32] && s[i:i+16] == s[i+32:i+48] && s[i:i+16] == s[i+48:i+64] {
			cutblock = i / 16
		}
	}
	oraclehelper = func(x []byte) []byte {
		t := make([]byte, frontpad, len(x)+frontpad)
		t = append(t, x...)
		t = oraclemoderate(t)
		return t[cutblock*16 : len(t)]
	}
}

// BreakECBModerate decrypts a ciphertext received from the oracle function (defined above)
// It does so by repeated calls to the oracle
// This solves http://cryptopals.com/sets/2/challenges/14/
func BreakECBModerate() []byte {
	setupHelper()
	chosens := genChosenCiphersEasy()
	var decrypted bytes.Buffer
	previous := make([]byte, aes.BlockSize, len(chosens[0]))
	for i := 0; i < len(chosens[0]); i += aes.BlockSize {
		previous = decrypt16bytesModerate(chosens, previous, i)
		decrypted.Write(previous)
	}
	return decrypted.Bytes()
}

func decrypt16bytesModerate(chosens [][]byte, previous []byte, index int) []byte {
	decrypted := make([]byte, 0, aes.BlockSize)
	for i := len(chosens) - 1; i >= 0; i-- {
		previous = previous[1:len(previous)]
		dec := decryptbyteModerate(chosens[i][index:index+aes.BlockSize], previous)
		previous = append(previous, dec)
		decrypted = append(decrypted, dec)
	}
	return decrypted
}

func decryptbyteModerate(chosen, previous []byte) byte {
	previous = append(previous, byte(0))
	for i := 0; i < 255; i++ {
		previous[aes.BlockSize-1] = byte(i)
		if bytes.Equal(oraclehelper(previous)[0:aes.BlockSize], chosen) {
			return byte(i)
		}
	}
	return 0
}

func genChosenCiphersModerate() [][]byte {
	chosens := make([][]byte, 0, aes.BlockSize)
	prefix := make([]byte, 0, aes.BlockSize-1)
	chosens = append(chosens, oraclehelper(prefix))
	var x byte
	for i := 0; i < aes.BlockSize-1; i++ {
		prefix = append(prefix, x)
		chosens = append(chosens, oraclehelper(prefix))
	}
	return chosens
}
