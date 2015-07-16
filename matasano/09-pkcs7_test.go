package matasano

import "testing"

func TestPadPCKCS7(t *testing.T) {
	inputs := []string{"YELLOW SUBMARINE", "TWENTY BYTELONG PARTYELLOW SUBMARINERS", "YELLOW", "20 YELLOW SUBMARINES"}
	expected := []string{"YELLOW SUBMARINE\x04\x04\x04\x04", "TWENTY BYTELONG PARTYELLOW SUBMARINERS\x02\x02", "YELLOW\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e",
		"20 YELLOW SUBMARINES\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14"}
	for i, input := range inputs {
		result := padPKCS7([]byte(input), 20)
		if string(result) != expected[i] {
			t.Fatalf("PKCS#7 padding failed. Expected %x - Received %x", expected[i], result)
		}
	}
}
