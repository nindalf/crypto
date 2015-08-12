package matasano

import "testing"

func TestECBCBCOracle(t *testing.T) {
	plaintexts := []string{
		"Lorem ipsum dolor sit amet, consectetur000000000000000000000000000000000000000000000000 adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.",
		"Lorem ipsum dolor sit amet, consectetur adipiscing00000000000000000000000000000000 elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. 00000000000000000000000000000000Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.",
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit,abcdefghijklmnopqrstuvwxyz012345 sed do eiusmod tempor incididunt ut labore et dolore magna ali/abcdefghijklmnopqrstuvwxyz012345qua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat."}
	for _, plaintext := range plaintexts {
		ciphers, expected := generateCiphertexts([]byte(plaintext))
		predicted := OracleAES(ciphers)
		for i := range expected {
			if expected[i] != predicted[i] {
				if expected[i] == 1 {
					t.Fatalf("Plaintext - %s\nExpected Oracle to detect AES ECB but found CBC", plaintext)
				} else {
					t.Fatalf("Plaintext - %s\nExpected Oracle to detect AES CBC but found ECB", plaintext)
				}
			}
		}
	}
}

func TestRandbytes(t *testing.T) {
	for i := 2; i < 20; i++ {
		r := randbytes(i)
		if len(r) != i {
			t.Fatalf("Expected byte slice of length %d, got length %d instead", i, len(r))
		}
	}
}
