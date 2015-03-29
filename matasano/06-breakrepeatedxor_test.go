package matasano

import (
	"encoding/base64"
	"io/ioutil"
	"testing"
)

const (
	datafile = "06-data.txt"
)

func TestDecryptFile(t *testing.T) {
	actkey, plaintext := DecryptFile(datafile)
	expkey := "Terminator X: Bring the noise"
	if expkey != actkey {
		t.Fatalf("Inputs - %s\nExptected key - %s\nActual key - %s\nPlaintext -\n%s", datafile, expkey, actkey, plaintext)
	}
}

func TestKeySize(t *testing.T) {
	encoded, err := ioutil.ReadFile(datafile)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, (len(encoded)/4)*3)
	base64.StdEncoding.Decode(b, encoded)
	expected := 29
	actual := keysize(b)
	if expected != actual {
		t.Fatalf("Inputs - %s\nExptected - %d\nActual - %d", datafile, expected, actual)
	}
}

func TestHammingdistance(t *testing.T) {
	in1 := []byte("this is a test")
	in2 := []byte("wokka wokka!!!")
	expected := 37
	actual := hammingdistance(in1, in2)
	if expected != actual {
		t.Fatalf("Inputs - %s\t%s\nExptected - %d\nActual - %d", in1, in2, expected, actual)
	}
}
