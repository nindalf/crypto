package matasano

import (
	"bytes"
	"fmt"
)

func breakECB() {
	blocksize := 16
	chosens := genChosenCiphers(blocksize)
	var decrypted bytes.Buffer
	previous := make([]byte, blocksize-1)
	for i := 0; i < unknownTextLen(); i += blocksize {
		c := make([][]byte, 0, blocksize-1)
		for j := 0; j < blocksize-1; j++ {
			c = append(c, chosens[j][i:i+blocksize])
		}
		previous = decrypt16bytes(c, previous)
		decrypted.Write(previous)
	}
	fmt.Println(decrypted.String())
}

func decrypt16bytes(chosens [][]byte, previous []byte) []byte {
	decrypted := make([]byte, 0, 16)
	for i := 14; i >= 0; i-- {
		previous = previous[1:len(previous)]
		dec := decryptbyte(chosens[i], previous)
		previous = append(previous, dec)
		decrypted = append(decrypted, dec)
	}
	return decrypted
}

func decryptbyte(chosen, previous []byte) byte {
	c := string(chosen)
	for i := 0; i < 255; i++ {
		p := append(previous, byte(i))
		if string(oracle(p)[0:16]) == c {
			return byte(i)
		}
	}
	return 0
}

func genChosenCiphers(blocksize int) [][]byte {
	chosens := make([][]byte, 0, blocksize-1)
	prefix := make([]byte, 1, blocksize-1)
	var x byte
	for i := 0; i < blocksize-1; i++ {
		chosens = append(chosens, oracle(prefix))
		prefix = append(prefix, x)
	}
	return chosens
}

func unknownTextLen() int {
	var b []byte
	return len(oracle(b))
}

//  a function that produces: AES-128-ECB(b || unknown-string, random-key)
var key = randbytes(16)

func oracle(b []byte) []byte {
	plaintext := []byte("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	dec := make([]byte, (3*len(plaintext))/4)
	DecodeBase64(dec, plaintext)
	b = append(b, dec...)
	b = padPKCS7(b, 16)
	EncryptAESECB(b, key)
	return b
}
