package matasano

import (
	"bytes"
	"errors"
	"math/rand"
	"time"
)

//  a function that produces: AES-128-ECB(b || unknown-string, random-key)
func oraclehard(b []byte) []byte {
	plaintext := []byte("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	dec := make([]byte, (3*len(plaintext))/4)
	DecodeBase64(dec, plaintext)
	rand.Seed(time.Now().UnixNano())
	r := randbytes(rand.Intn(40))
	r = append(r, b...)
	r = append(r, dec...)
	r = padPKCS7(r, 16)
	EncryptAESECB(r, rkey)
	return r
}

// BreakECBHard decrypts a ciphertext received from the oracle function (defined above)
// It does so by repeated calls to the oracle
// This solves http://cryptopals.com/sets/2/challenges/14/
func BreakECBHard() []byte {
	chosens := genChosenCiphersEasy()
	var decrypted bytes.Buffer
	previous := make([]byte, bsize, len(chosens[0]))
	for i := 0; i < len(chosens[0]); i += bsize {
		previous = decrypt16bytesEasy(chosens, previous, i)
		decrypted.Write(previous)
	}
	return decrypted.Bytes()
}

func genChosenCiphersHard() [][]byte {
	chosens := make([][]byte, 0, bsize)
	existing := make(map[string]bool)
	chosen := make([]byte, 64)
	for len(chosens) != bsize {
		b := oraclehard(chosen)
		lastblock := string(b[len(b)-16 : len(b)])
		if _, ok := existing[lastblock]; ok == false {
			chosens = append(chosens, b)
		}
	}
	return chosens
}

// encrypts a 16 byte block under the uknown key
// its a little complicated to get a 16 byte block encrypted since we don't know where it will be
func encryptBlock(b []byte) ([]byte, error) {
	if len(b) != 16 {
		return b, errors.New("incorrect length")
	}
	pad := make([]byte, 32)
	block := make([]byte, 0, 80)
	block = append(block, pad...)
	block = append(block, b...)
	block = append(block, pad...)
	enc := oraclehard(block)
	// if the pads are on the 16-byte boundaries, they will generate 4 similar blocks
	for similarBlocks(string(enc)) < 4 {
		enc = oraclehard(block)
	}
	s := string(enc)
	for i := 0; i < len(s); i += 16 {
		if s[i:i+16] == s[i+16:i+32] && s[i:i+16] != s[i+32:i+48] && s[i:i+16] == s[i+48:i+64] && s[i:i+16] == s[i+64:i+80] {
			return []byte(s[i+32 : i+48]), nil
		}
	}
	return b, errors.New("couldn't find the encrypted block")
}
