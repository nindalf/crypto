package matasano

import "testing"

func TestCTREncryptDecrypt(t *testing.T) {
	text := []byte("ATTACK AT DAWN!!ATTACK AT DAWN!!ATTACK AT DAWN!!ATTACK AT DAWN!!")
	expected := "ATTACK AT DAWN!!ATTACK AT DAWN!!ATTACK AT DAWN!!ATTACK AT DAWN!!"
	key := []byte("YELLOW SUBMARINE")

	iv := EncryptAESCTR(text, key)
	if string(text) == expected {
		t.Fatalf("Failed to encrypt - %s", expected)
	}

	DecryptAESCTR(text, key, iv)
	if string(text) != expected {
		t.Fatalf("Failed to decrypt - %s", expected)
	}
}
