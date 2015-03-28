package matasano

import "fmt"

// EncryptXor encrypts the plaintext using repeating-key XOR
// This solves http://cryptopals.com/sets/1/challenges/5/
func EncryptXor(plaintext, key []byte) []byte {
	for i := range plaintext {
		keybyte := key[i%len(key)]
		plaintext[i] = plaintext[i] ^ keybyte
	}
	fmt.Println(string(str2hex(plaintext)))
	return str2hex(plaintext)
}
