package matasano

import "testing"

func TestDecryptAES(t *testing.T) {
	DecryptAES("07-data.txt", []byte("YELLOW SUBMARINE"))
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

// test vectors reversed from previous TestMixColumns
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
