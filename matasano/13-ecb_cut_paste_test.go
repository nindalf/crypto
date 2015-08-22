package matasano

import (
	"strings"
	"testing"
)

func TestCreateAdminProfile(t *testing.T) {
	profile := decryptProfile(CreateAdminProfile())
	expectedlen := 3
	if len(profile) != expectedlen {
		t.Fatalf("Returned profile is not of length %d", expectedlen)
	}
	if profile["role"] != "admin" {
		t.Fatalf("Role is not admin")
	}
}

func TestKvencoder(t *testing.T) {
	input := map[string]string{"a": "first", "b": "2nd", "c&b=malicious": "3", "c": "3&b=malicious", "d": "4ourth", "e": "b=malicious"}
	expectedKeys := 3
	actual := kvencoder(input)
	if strings.Contains(actual, "malicious") {
		t.Fatalf("Encoded string contains malicious input - %s", actual)
	}
	if strings.Count(actual, "=") != expectedKeys || strings.Count(actual, "&") != expectedKeys-1 {
		t.Fatalf("Encoded string contains incorrect number of params - %s", actual)
	}
}

func TestKvencoderBad(t *testing.T) {
	input := map[string]string{"a": "first", "b": "2nd", "c&b=malicious": "3", "c": "3&b=malicious", "d": "4ourth", "e": "b=malicious"}
	keys := []string{"a", "b", "c&b=malicious", "3&b=malicious", "d", "e"}
	actual := kvencoderBad(input, keys)
	expected := "a=first&b=2nd&d=4ourth"
	if expected != actual {
		t.Fatalf("Encoding failed. Expected - %s\tActual - %s\n", expected, actual)
	}
}

func TestKvdecoder(t *testing.T) {
	input := "a=first&b=2nd&d=4ourth"
	actual := kvdecoder(input)
	expected := map[string]string{"a": "first", "b": "2nd", "d": "4ourth"}
	if len(actual) != len(expected) {
		t.Fatalf("Failed to decode string.\nExpected length - %d\tActual length - %d", len(expected), len(actual))
	}
	for k := range expected {
		if expected[k] != actual[k] {
			t.Fatalf("Failed to decode string. Different values found for key - %s\nExpected - %s\tActual - %s", k, expected[k], actual[k])
		}
	}
}
