package matasano

import (
	"bytes"
	"fmt"
	"math/rand"
	"time"
)

var plaintexts = []string{
	"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
	"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
	"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"}

// CBCPaddingOracle just chills out
func CBCPaddingOracle(b []byte, iv []uint32) []byte {
	var decrypted bytes.Buffer
	for i := 16; i < len(b); i += 16 {
		dec := decryptCBCBlock(b[0:i+16], iv)
		decrypted.Write(dec)
	}
	return decrypted.Bytes()
}

// decrypts the last 16 bytes of block b using calls to the padding oracle
func decryptCBCBlock(b []byte, iv []uint32) []byte {
	p, c := make([]byte, 16), make([]byte, len(b))
	for i := 15; i >= 0; i-- {
		copy(c, b)
		paddingbyte := byte(16 - i)
		// fmt.Println(len(c)-32+i, paddingbyte, c[len(c)-32:len(c)])
		for j := 1; j < 16-i; j++ {
			c[len(c)-j-16] = c[len(c)-j-16] ^ p[16-j] ^ paddingbyte
		}
		// fmt.Println(len(c)-32+i, paddingbyte, c[len(c)-32:len(c)])
		// fmt.Println("---")
		for k := 0; k < 256; k++ {
			c[len(c)-32+i] = c[len(c)-32+i] ^ byte(k) ^ paddingbyte
			if isPaddingValid(c, iv) {
				fmt.Println(c)
				p[i] = byte(k)
				break
			}
		}
	}
	return p
}

// 15 14 13

func encrypt17() ([]byte, []uint32) {
	rand.Seed(time.Now().UnixNano())
	// s := plaintexts[rand.Intn(len(plaintexts))]
	s := plaintexts[1]
	b := []byte(s)
	b = padPKCS7(b, 16)
	iv := EncryptAESCBC(b, rkey)
	return b, iv
}

// isPaddingValid decrypts the ciphertext and returns true if the padding is valid
func isPaddingValid(b []byte, iv []uint32) bool {
	DecryptAESCBC(b, rkey, iv)
	_, err := stripPKCS7(b)
	return err == nil
}
