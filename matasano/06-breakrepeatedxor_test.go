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
	DecryptFile(datafile)
	t.Fail() // This has not been completed yet
}

func TestKeySize(t *testing.T) {
	encoded, err := ioutil.ReadFile(datafile)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, (len(encoded)/4)*3)
	base64.StdEncoding.Decode(b, encoded)
	expected := 28
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
