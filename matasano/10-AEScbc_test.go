package matasano

import (
	"io/ioutil"
	"strings"
	"testing"
)

func TestCBCEncryptDecrypt(t *testing.T) {
	text := []byte("ATTACK AT DAWN!!ATTACK AT DAWN!!ATTACK AT DAWN!!ATTACK AT DAWN!!")
	expected := "ATTACK AT DAWN!!ATTACK AT DAWN!!ATTACK AT DAWN!!ATTACK AT DAWN!!"
	key := []byte("YELLOW SUBMARINE")

	encryptAESCBC(text, key)
	if string(text) == expected {
		t.Fatalf("Failed to encrypt - %s", expected)
	}

	decryptAESCBC(text, key)
	if string(text) != expected {
		t.Fatalf("Failed to decrypt - %s", expected)
	}
}

func TestDecryptAESCBC(t *testing.T) {
	encoded, _ := ioutil.ReadFile("10-data.txt")
	b := make([]byte, (len(encoded)/4)*3)
	DecodeBase64(b, encoded)

	key := []byte("YELLOW SUBMARINE")

	decryptAESCBC(b, key)
	expectedstart := "I'm back and I'm ringin' the bell"
	if !strings.HasPrefix(string(b), expectedstart) {
		t.Fatalf("Start of the plaintext was not - %s", expectedstart)
	}
}
