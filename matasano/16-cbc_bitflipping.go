package matasano

import "strings"

// FlipCBC modifies the encrypted text such that the last block contains ";admin=true;"
// Assumes that the input was a multiple of 16 and the last block of ciphertext is padding only
// This solves http://cryptopals.com/sets/2/challenges/16
func FlipCBC(b []byte) []byte {
	x := b[len(b)-48 : len(b)-32]
	old := []byte("und%20of%20bacon")
	new := []byte("unds;admin=true;")
	for i := range x {
		x[i] = x[i] ^ old[i] ^ new[i]
	}
	return b
}

func encrypt16(input string) ([]byte, []uint32) {
	input = strings.Replace(input, ";", "", -1)
	input = strings.Replace(input, "=", "", -1)
	b := []byte("comment1=cooking%20MCs;userdata=" + input + ";comment2=%20like%20a%20pound%20of%20bacon")
	b = padPKCS7(b, 16)
	iv := EncryptAESCBC(b, rkey)
	return b, iv
}

// returns true if b contains ";admin=true;"
func decrypt16(b []byte, iv []uint32) bool {
	DecryptAESCBC(b, rkey, iv)
	s := string(b)
	return strings.Contains(s, "admin=true")
}
