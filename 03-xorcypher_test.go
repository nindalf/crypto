package matasano

import "testing"

func TestDecryptXor(t *testing.T) {
	input := []byte("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	expected := "Cooking MC's like a pound of bacon"
	if expected != string(DecryptXor(input)) {
		t.Fail()
	}
}
