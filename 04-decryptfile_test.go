package matasano

import "testing"

func TestFindLine(t *testing.T) {
	expected := "Now that the party is jumping\n"
	decrypted, line, key := FindLine("04-data.txt")
	if expected != string(decrypted) {
		t.Fatalf("Expected - %s\nFound - %s from %s, Key - %s", expected, string(decrypted), string(line), string(key))
	}
}
