package matasano

import "testing"

func TestFlipCBC(t *testing.T) {
	//input of length 6+16 so that the length of the plaintext is a multiple of 16
	input := "123456admin=true7890123"
	b := encrypt16(input)
	if decrypt16(b) == true {
		t.Fatalf("Found string %s in the plaintext", "admin=true")
	}
	b = encrypt16(input)
	FlipCBC(b)
	if decrypt16(b) == false {
		t.Fatalf("Did not find string %s in the plaintext", "admin=true")
	}
}
