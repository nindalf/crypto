package matasano

import (
	"bytes"
	"fmt"
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

// CBCPaddingOracle just chills out
func CBCPaddingOracle(b, iv []byte) []byte {
	var decrypted bytes.Buffer
	t := make([]byte, 16)

	for len(b) > 0 {
		copy(t, b[0:16])
		dec := breakCBCBlock(b[0:16], iv, len(b) == 16)
		copy(iv, t)
		b = b[16:len(b)]
		decrypted.Write(dec)
	}
	return decrypted.Bytes()
}

// decrypts the first 16 bytes of block b using calls to the padding oracle
func breakCBCBlock(b, iv []byte, lastblock bool) []byte {
	p := make([]byte, 16)
	ivc := make([]byte, 16)
	for i := 15; i >= 0; i-- {
		copy(ivc, iv)
		paddingbyte := byte(16 - i)

		for j := 15; j > i; j-- {
			ivc[j] ^= p[j] ^ paddingbyte
		}

		temp := iv[i]
		for k := 0; k < 256; k++ {
			if lastblock && i == 15 && k == 1 {
				continue
			}
			ivc[i] = temp ^ byte(k) ^ paddingbyte
			if isPaddingValid(b, ivc) {
				p[i] = byte(k)
				break
			}
			if k == 255 {
				fmt.Println("failure")
			}
		}
	}
	return p
}

func encrypt17(s string) ([]byte, []byte) {
	b := []byte(s)
	b = PadPKCS7(b, 16)
	iv := randbytes(16)
	EncryptAESCBC(b, rkey, iv)
	return b, iv
}

// isPaddingValid decrypts the ciphertext and returns true if the padding is valid
func isPaddingValid(b, iv []byte) bool {
	c := make([]byte, 16)
	copy(c, b)
	DecryptAESCBC(c, rkey, iv)
	_, err := StripPKCS7(c)
	return err == nil
}
