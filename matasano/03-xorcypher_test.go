package matasano

import "testing"

func TestDecryptXor(t *testing.T) {
	input := []byte("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	expected := "Cooking MC's like a pound of bacon"
	decrypted, rank, key := DecryptXor(hex2str(input))
	if expected != string(decrypted) {
		t.Logf("Expected - %s\nFound - %sRank - %f, Key - %s", expected, string(decrypted), rank, string(key))
		t.Fail()
	}
}
