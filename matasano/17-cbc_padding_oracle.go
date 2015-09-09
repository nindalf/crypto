package matasano

import (
	"bytes"
	"crypto/aes"
)

var plaintexts17 = []string{
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

// CBCPaddingOracle breaks a ciphertext encrypted using CBC-mode block cipher
// It does so by changing ciphertext bytes and checking if the corresponding padding is valid
// This solves http://cryptopals.com/sets/3/challenges/17
func CBCPaddingOracle(b, iv []byte) []byte {
	var decrypted bytes.Buffer
	t := make([]byte, aes.BlockSize)

	for len(b) > 0 {
		copy(t, b[:aes.BlockSize])
		dec := breakCBCBlock(b[:aes.BlockSize], iv, len(b) == 16)
		copy(iv, t)
		b = b[aes.BlockSize:]
		decrypted.Write(dec)
	}
	return decrypted.Bytes()
}

// decrypts the first 16 bytes of block b using calls to the padding oracle
func breakCBCBlock(b, iv []byte, lastblock bool) []byte {
	p := make([]byte, aes.BlockSize)
	c := make([]byte, aes.BlockSize)
	ivc := make([]byte, aes.BlockSize)
	for i := 15; i >= 0; i-- {
		copy(ivc, iv)
		paddingbyte := byte(16 - i)

		for j := 15; j > i; j-- {
			ivc[j] ^= p[j] ^ paddingbyte
		}

		temp := iv[i]
		for k := 0; k < 256; k++ {
			if lastblock && i == 15 && byte(k) == paddingbyte {
				continue
			}
			ivc[i] = temp ^ byte(k) ^ paddingbyte
			if isPaddingValid(c, b, ivc) {
				p[i] = byte(k)
				break
			}
		}
	}
	return p
}

func encrypt17(s string) ([]byte, []byte) {
	b := []byte(s)
	b = PadPKCS7(b, 16)
	iv := randbytes(aes.BlockSize)
	cbcEnc.(ivSetter).SetIV(iv)
	cbcEnc.CryptBlocks(b, b)
	return b, iv
}

// isPaddingValid decrypts the ciphertext and returns true if the padding is valid
func isPaddingValid(dst, src, iv []byte) bool {
	cbcDec.(ivSetter).SetIV(iv)
	cbcDec.CryptBlocks(dst, src)
	_, err := StripPKCS7(dst)
	return err == nil
}
