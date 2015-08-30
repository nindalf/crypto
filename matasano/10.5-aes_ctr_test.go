package matasano

import "testing"

func TestCTREncryptDecrypt(t *testing.T) {
	input := "ATTACK AT DAWN!!ATTACK AT DAWN!!ATTACK AT DAWN!!ATTACK AT DAWN!!"
	for i := 1; i < len(input); i++ {
		testCTR(t, input[0:i])
	}
}

func testCTR(t *testing.T, input string) {
	b := []byte(input)
	key := []byte("YELLOW SUBMARINE")

	iv := EncryptAESCTR(b, key)
	if string(b) == input {
		t.Fatalf("Failed to encrypt - %s", input)
	}

	DecryptAESCTR(b, key, iv)
	if string(b) != input {
		t.Fatalf("Failed to decrypt - %s", input)
	}
}
