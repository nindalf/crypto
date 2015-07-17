package matasano

import (
	"io/ioutil"
	"strings"
	"testing"
)

const datafile07 = "07-data.txt"

func TestDecryptAESECB(t *testing.T) {
	encoded, err := ioutil.ReadFile(datafile07)
	if err != nil {
		t.Fatal(err)
	}

	b := make([]byte, (len(encoded)/4)*3)
	DecodeBase64(b, encoded)
	key := []byte("YELLOW SUBMARINE")

	DecryptAESECB(b, key)
	expectedstart := "I'm back and I'm ringin' the bell"
	if !strings.HasPrefix(string(b), expectedstart) {
		t.Fatalf("Start of the plaintext was not - %s", expectedstart)
	}
}

func TestECBEncryptDecrypt(t *testing.T) {
	text := []byte("ATTACK AT DAWN!!")
	expected := "ATTACK AT DAWN!!"
	key := []byte("YELLOW SUBMARINE")

	EncryptAESECB(text, key)
	if string(text) == expected {
		t.Fatalf("Failed to encrypt - %s", expected)
	}

	DecryptAESECB(text, key)
	if string(text) != expected {
		t.Fatalf("Failed to decrypt - %s", expected)
	}
}
