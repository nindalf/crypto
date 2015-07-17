package matasano

import (
	"math/rand"
	"testing"
	"time"
)

func TestKeyExpansion(t *testing.T) {
	key := "YELLOW SUBMARINE"
	expandedkey := []uint32{0x594f5552, 0x45574249, 0x4c204d4e, 0x4c534145, 0x632c792b,
		0x6a3d7f36, 0x22024f01, 0x4c1f5e1b, 0x6448311a, 0x162b5462, 0x8d8fc0c1, 0xbda2fce7,
		0xca82b3a9, 0x6e451173, 0x19965697, 0x1fbd41a6, 0x4dcf7cd5, 0xe6a3b2c1, 0x3dabfd6a,
		0xcc713096, 0x25ea9643, 0xe447f534, 0xad06fb91, 0xcfbe8e18, 0x1df76122, 0x6522d7e3,
		0x6fd6c, 0xd56be5fd, 0x4cbbdaf8, 0x3517c023, 0x5452afc3, 0x462dc835, 0xea518b73,
		0x1b0cccef, 0xc2903ffc, 0x72ae2d7, 0x2e7ff487, 0xaba76b84, 0xcc5c639f, 0x88a24097,
		0x4738cc4b, 0x70d7bc38, 0x44187be4, 0x9f3d7dea}
	actual := keyExpansion([]byte(key))
	for i := range expandedkey {
		if expandedkey[i] != actual[i] {
			t.Fatalf("Expanded key for %s is incorrect\n", key)
		}
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := "PURPLE SIDEKICKS"
	expkey := keyExpansion([]byte(key))
	enc := func(state []uint32) {
		encryptAES(state, expkey)
	}
	dec := func(state []uint32) {
		decryptAES(state, expkey)
	}
	testForwardAndInverse(t, enc, dec, "Encrypt")
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

func TestBothSubWords(t *testing.T) {
	testForwardAndInverse(t, subBytes, invSubBytes, "Substitution")
}

func TestTranspose(t *testing.T) {
	input := []uint32{0x8e9f01c6, 0x4ddc01c6, 0xa15801c6, 0xbc9d01c6}
	expected := []uint32{0x8e4da1bc, 0x9fdc589d, 0x01010101, 0xc6c6c6c6}
	transpose(input)
	for i := 0; i < 4; i++ {
		if input[i] != expected[i] {
			t.Fatalf("Transpose failed at index %d. Expected - 0x%x, Received - 0x%x", i, expected[i], input[i])
		}
	}
}

func TestTransposeInverse(t *testing.T) {
	testForwardAndInverse(t, transpose, transpose, "Transpose")
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
