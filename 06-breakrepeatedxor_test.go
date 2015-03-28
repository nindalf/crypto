package matasano

import "testing"

func TestHammingdistance(t *testing.T) {
	in1 := []byte("this is a test")
	in2 := []byte("wokka wokka!!!")
	expected := 37
	actual := hammingdistance(in1, in2)
	if expected != actual {
		t.Fatalf("Inputs - %s\t%s\nExptected - %d\nActual - %d", in1, in2, expected, actual)
	}
}
