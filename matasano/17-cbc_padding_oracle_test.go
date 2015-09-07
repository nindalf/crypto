package matasano

import "testing"

func TestCBCPaddingOracle(t *testing.T) {
	for _, s := range plaintexts17 {
		encrypted, iv := encrypt17(s)

		plaintext := CBCPaddingOracle(encrypted, iv)
		plaintext, err := StripPKCS7(plaintext)
		if err != nil || string(plaintext) != s {
			t.Fatalf("Expected - %s\nActual - %s", s, string(plaintext))
		}
	}
}
