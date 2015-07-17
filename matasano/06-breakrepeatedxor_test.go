package matasano

import (
	"io/ioutil"
	"testing"
)

const datafile06 = "06-data.txt"

func TestDecryptRepeatedXOR(t *testing.T) {
	encoded, err := ioutil.ReadFile(datafile06)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, (len(encoded)/4)*3)
	DecodeBase64(b, encoded)

	actkey, plaintext := DecryptRepeatedXOR(b)
	expkey := "Terminator X: Bring the noise"
	if expkey != actkey {
		t.Fatalf("Inputs - %s\nExptected key - %s\nActual key - %s\nPlaintext -\n%s", datafile06, expkey, actkey, plaintext)
	}
}

func TestKeySize(t *testing.T) {
	encoded, err := ioutil.ReadFile(datafile06)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, (len(encoded)/4)*3)
	DecodeBase64(b, encoded)
	expected := 29
	actual := keysize(b)
	if expected != actual {
		t.Fatalf("Inputs - %s\nExptected - %d\nActual - %d", datafile06, expected, actual)
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
