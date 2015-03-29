package matasano

// EncryptXor encrypts the plaintext using repeating-key XOR
// This solves http://cryptopals.com/sets/1/challenges/5/
func EncryptRepeatedXor(plaintext, key []byte) []byte {
	for i := range plaintext {
		keybyte := key[i%len(key)]
		plaintext[i] = plaintext[i] ^ keybyte
	}
	return str2hex(plaintext)
}

func DecryptRepeatedXor(ciphertext, key []byte) []byte {
	for i := range ciphertext {
		keybyte := key[i%len(key)]
		ciphertext[i] = ciphertext[i] ^ keybyte
	}
	return ciphertext
}
