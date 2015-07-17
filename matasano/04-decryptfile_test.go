package matasano

import (
	"bytes"
	"io/ioutil"
	"testing"
)

const datafile04 = "04-data.txt"

func TestFindXORLine(t *testing.T) {
	b, err := ioutil.ReadFile(datafile04)
	if err != nil {
		t.Fatal(err)
	}

	lines := bytes.Split(b, []byte("\n"))
	decrypted, line, key := FindXORLine(lines)
	expected := "Now that the party is jumping\n"
	if expected != string(decrypted) {
		t.Fatalf("Expected - %s\nFound - %s from %s, Key - %s", expected, string(decrypted), string(line), string(key))
	}
}
