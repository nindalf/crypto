package matasano

import (
	"math/rand"
	"testing"
	"time"
)

func TestDecryptAES(t *testing.T) {
	plaintext := DecryptAES("07-data.txt", []byte("YELLOW SUBMARINE"))
	expectedstart := "I'm back and I'm"
	if string(plaintext[0:16]) != expectedstart {
		t.Fatalf("Start of the plaintext was not - %s", expectedstart)
	}
}

func TestBoth(t *testing.T) {
	plaintext := "ATTACK AT DAWN!!"
	key := "YELLOW SUBMARINE"
	expkey := keyExpansion([]byte(key))

	b := []byte(plaintext)
	state := make([]uint32, len(b)/4)
	for i := 0; i < len(state); i += 4 {
		for j := 0; j < 4; j++ {
			state[i+j] = uint32(b[i*4+j])<<24 | uint32(b[(i+1)*4+j])<<16 | uint32(b[(i+2)*4+j])<<8 | uint32(b[(i+3)*4+j])
		}
	}

	for i := 0; i < len(state); i += 4 {
		encrypt(state[i:i+4], expkey)
	}

	for i := 0; i < len(state); i += 4 {
		decrypt(state[i:i+4], expkey)
	}

	for i := 0; i < len(state); i += 4 {
		for j := 0; j < 4; j++ {
			b[(i+0)*4+j] = byte(state[i+j] >> 24)
			b[(i+1)*4+j] = byte((state[i+j] >> 16) & 0xff)
			b[(i+2)*4+j] = byte((state[i+j] >> 8) & 0xff)
			b[(i+3)*4+j] = byte((state[i+j]) & 0xff)
		}
	}
	if string(b) != plaintext {
		t.Fatalf("Encrypt and Decrypt do not invert each other.")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := "PURPLE SIDEKICKS"
	expkey := keyExpansion([]byte(key))
	enc := func(state []uint32) {
		encrypt(state, expkey)
	}
	dec := func(state []uint32) {
		decrypt(state, expkey)
	}
	testForwardAndInverse(t, enc, dec, "Encrypt")
}

func TestKeyExpansion(t *testing.T) {
	key := "YELLOW SUBMARINE"
	expandedkey := []uint32{1497713740, 1331109971, 1430408513, 1380535877, 1667899980,
		742195743, 2038386526, 724959515, 1679199677, 1210814370, 827638012, 442679783,
		3396213023, 2185598653, 3004257857, 2842924966, 1306934732, 3483609969, 2092105008,
		3586222742, 635743695, 3930523326, 2532703118, 1127518488, 493158613, 4146202219,
		1641545189, 585329917, 1278563398, 3138867757, 3670061000, 4163093301, 3927687687,
		1359777834, 2345418722, 1945107671, 783010952, 2141674658, 4100678464, 2273615767,
		1198539935, 953620541, 3434904445, 1262019818}
	actual := keyExpansion([]byte(key))
	for i := range expandedkey {
		if expandedkey[i] != actual[i] {
			t.Fatalf("Expanded key for %s is incorrect\n", key)
		}
	}
}

func TestBothSubWords(t *testing.T) {
	testForwardAndInverse(t, subBytes, invSubBytes, "Substitution")
}

// test vectors from https://en.wikipedia.org/wiki/Rijndael_mix_columns#Test_vectors_for_MixColumns.28.29.3B_not_for_InvMixColumns
func TestMixColumns(t *testing.T) {
	input := []uint32{0xdbf201c6, 0x130a01c6, 0x532201c6, 0x455c01c6}
	expected := []uint32{0x8e9f01c6, 0x4ddc01c6, 0xa15801c6, 0xbc9d01c6}
	mixColumns(input)
	for i := 0; i < 4; i++ {
		if input[i] != expected[i] {
			t.Fatalf("Mix columns failed at index %d. Expected - 0x%x, Received - 0x%x", i, expected[i], input[i])
		}
	}
}

// test vectors reversed from TestMixColumns
func TestInvMixColumns(t *testing.T) {
	input := []uint32{0x8e9f01c6, 0x4ddc01c6, 0xa15801c6, 0xbc9d01c6}
	expected := []uint32{0xdbf201c6, 0x130a01c6, 0x532201c6, 0x455c01c6}
	invMixColumns(input)
	for i := 0; i < 4; i++ {
		if input[i] != expected[i] {
			t.Fatalf("Mix columns failed at index %d. Expected - 0x%x, Received - 0x%x", i, expected[i], input[i])
		}
	}
}

func TestBothMixColumns(t *testing.T) {
	testForwardAndInverse(t, mixColumns, invMixColumns, "Mix columns")
}

func TestShiftRows(t *testing.T) {
	input := []uint32{0x8e9f01c6, 0x4ddc01c6, 0xa15801c6, 0xbc9d01c6}
	expected := []uint32{0x8e9f01c6, 0xdc01c64d, 0x01c6a158, 0xc6bc9d01}
	shiftRows(input)
	for i := 0; i < 4; i++ {
		if input[i] != expected[i] {
			t.Fatalf("Shift rows failed at index %d. Expected - 0x%x, Received - 0x%x", i, expected[i], input[i])
		}
	}
}

func TestInvShiftRows(t *testing.T) {
	input := []uint32{0x8e9f01c6, 0x4ddc01c6, 0xa15801c6, 0xbc9d01c6}
	expected := []uint32{0x8e9f01c6, 0xc64ddc01, 0x01c6a158, 0x9d01c6bc}
	invShiftRows(input)
	for i := 0; i < 4; i++ {
		if input[i] != expected[i] {
			t.Fatalf("Shift rows failed at index %d. Expected - 0x%x, Received - 0x%x", i, expected[i], input[i])
		}
	}
}

func TestBothShiftRows(t *testing.T) {
	testForwardAndInverse(t, shiftRows, invShiftRows, "Shift rows")
}

func testForwardAndInverse(t *testing.T, forward, inverse func([]uint32), name string) {
	rand.Seed(time.Now().UnixNano())
	input, expected := make([]uint32, 4), make([]uint32, 4)
	for i := 0; i < 10; i++ {
		for j := range input {
			n := rand.Uint32()
			input[j], expected[j] = n, n
		}
		forward(input)
		inverse(input)
		for j := range input {
			if input[j] != expected[j] {
				t.Fatalf("%s forward and inverse failed. Expected - %d, Received %d", name, expected[j], input[j])
			}
		}
	}
}
