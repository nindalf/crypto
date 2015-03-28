package matasano

import "testing"

func TestFindLine(t *testing.T) {
	expected := "Now that the party is jumping\n"
	result, line := FindLine("04-data.txt")
	if expected != string(result) {
		t.FailNow()
	}
}
