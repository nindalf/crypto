package matasano

import (
	"io/ioutil"
	"strings"
	"testing"
)

const datafile10 = "10-data.txt"

func TestCBCEncryptDecrypt(t *testing.T) {
	text := []byte("ATTACK AT DAWN!!ATTACK AT DAWN!!ATTACK AT DAWN!!ATTACK AT DAWN!!")
	expected := "ATTACK AT DAWN!!ATTACK AT DAWN!!ATTACK AT DAWN!!ATTACK AT DAWN!!"
	key := []byte("YELLOW SUBMARINE")

	iv := EncryptAESCBC(text, key)
	if string(text) == expected {
		t.Fatalf("Failed to encrypt - %s", expected)
	}

	DecryptAESCBC(text, key, iv)
	if string(text) != expected {
		t.Fatalf("Failed to decrypt - %s", expected)
	}
}

func TestDecryptAESCBC(t *testing.T) {
	encoded, err := ioutil.ReadFile(datafile10)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, (len(encoded)/4)*3)
	DecodeBase64(b, encoded)

	key := []byte("YELLOW SUBMARINE")
	iv := []uint32{0, 0, 0, 0}

	DecryptAESCBC(b, key, iv)
	expectedstart := "I'm back and I'm ringin' the bell"
	if !strings.HasPrefix(string(b), expectedstart) {
		t.Fatalf("Start of the plaintext was not - %s", expectedstart)
	}
}
