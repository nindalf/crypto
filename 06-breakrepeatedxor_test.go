package matasano

import "testing"

func TestHammingdistance(t *testing.T) {
	in1 := []byte("this is a test")
	in2 := []byte("wokka wokka!!!")
	expecteddist := 37
	if expecteddist != hammingdistance(in1, in2) {
		t.Fail()
	}
}
