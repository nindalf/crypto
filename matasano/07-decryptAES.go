package matasano

import (
	"encoding/base64"
	"io/ioutil"
)

// DecryptAES decrypts a ciphertext encrypted with AES in ECB mode.
func DecryptAES(filepath string, key []byte) string {
	encoded, _ := ioutil.ReadFile(filepath)
	b := make([]byte, (len(encoded)/4)*3)
	base64.StdEncoding.Decode(b, encoded)
	return ""
}

func invShiftRows(state []uint32) {
	rotWordLeft(state[1], 1)
	rotWordLeft(state[2], 2)
	rotWordLeft(state[3], 3)
}

func invSubBytes(state []uint32) {
	for i := range state {
		state[i] = invSubWord(state[i])
	}
}

func addRoundKey(state, key []uint32) {
	for i := range state {
		state[i] = state[i] ^ key[i]
	}
}

func invMixColumns(state []uint32) {
	var i uint
	for ; i < 4; i++ {
		var a0, a1, a2, a3 byte
		a0 = byte((state[0] >> ((3 - i) * 8)) & 0xff)
		a1 = byte((state[1] >> ((3 - i) * 8)) & 0xff)
		a2 = byte((state[2] >> ((3 - i) * 8)) & 0xff)
		a3 = byte((state[3] >> ((3 - i) * 8)) & 0xff)

		var r0, r1, r2, r3 byte
		r0 = gMulBy14[a0] ^ gMulBy11[a1] ^ gMulBy13[a2] ^ gMulBy9[a3]
		r1 = gMulBy9[a0] ^ gMulBy14[a1] ^ gMulBy11[a2] ^ gMulBy13[a3]
		r2 = gMulBy13[a0] ^ gMulBy9[a1] ^ gMulBy14[a2] ^ gMulBy11[a3]
		r3 = gMulBy11[a0] ^ gMulBy13[a1] ^ gMulBy9[a2] ^ gMulBy14[a3]

		var mask uint32
		mask = 0xff << ((3 - i) * 8)
		mask = ^mask // used to clear those bits
		state[0] = (state[0] & mask) | (uint32(r0) << ((3 - i) * 8))
		state[1] = (state[1] & mask) | (uint32(r1) << ((3 - i) * 8))
		state[2] = (state[2] & mask) | (uint32(r2) << ((3 - i) * 8))
		state[3] = (state[3] & mask) | (uint32(r3) << ((3 - i) * 8))
	}
}

func mixColumns(state []uint32) {
	var i uint
	for ; i < 4; i++ {
		var a0, a1, a2, a3 byte
		a0 = byte((state[0] >> ((3 - i) * 8)) & 0xff)
		a1 = byte((state[1] >> ((3 - i) * 8)) & 0xff)
		a2 = byte((state[2] >> ((3 - i) * 8)) & 0xff)
		a3 = byte((state[3] >> ((3 - i) * 8)) & 0xff)

		var r0, r1, r2, r3 byte
		r0 = gMulBy2[a0] ^ gMulBy3[a1] ^ a2 ^ a3
		r1 = a0 ^ gMulBy2[a1] ^ gMulBy3[a2] ^ a3
		r2 = a0 ^ a1 ^ gMulBy2[a2] ^ gMulBy3[a3]
		r3 = gMulBy3[a0] ^ a1 ^ a2 ^ gMulBy2[a3]

		var mask uint32
		mask = 0xff << ((3 - i) * 8)
		mask = ^mask // used to clear those bits
		// fmt.Println(state[0])
		state[0] = (state[0] & mask) | (uint32(r0) << ((3 - i) * 8))
		state[1] = (state[1] & mask) | (uint32(r1) << ((3 - i) * 8))
		state[2] = (state[2] & mask) | (uint32(r2) << ((3 - i) * 8))
		state[3] = (state[3] & mask) | (uint32(r3) << ((3 - i) * 8))
	}
}

// based on https://en.wikipedia.org/wiki/Rijndael_key_schedule
// I've tried to optimise for readability.

// nwords - number of words. Values are 4, 6, 8 for 128, 192 and 256-bit
// Nb - number of words in an AES block. Constant 4. Implicitly assumed since I use uint32 in the implementation
// rounds - number of rounds. Values are 10, 12, 14 for 128, 192 and 256-bit

func keyExpansion(key []byte) []uint32 {
	keysize := len(key)
	nwords := (keysize / 4)
	rounds := nwords + 6 // don't know if this is a coincidence

	expkeys := make([]uint32, nwords*(rounds+1))
	// the key occupies the first nwords slots of the expanded key
	var i int
	for i < nwords {
		expkeys[i] = uint32(key[i*4])<<24 | uint32(key[i*4+1])<<16 | uint32(key[i*4+2])<<8 | uint32(key[i*4+3])
		i++
	}

	for i < nwords*(rounds+1) {
		// equivalent to
		// expkeys[i] = (subWord(rotWord(expkeys[i-1])) ^ rcon(1/nwords)) ^ expkeys[i-nwords]
		expkeys[i] = expkeys[i-1]
		expkeys[i] = rotWordLeft(expkeys[i], 1)
		expkeys[i] = subWord(expkeys[i])
		expkeys[i] ^= rcon(i/nwords - 1)
		expkeys[i] ^= expkeys[i-nwords]

		for j := 1; j <= 3; j++ {
			expkeys[i+j] = expkeys[i+j-1] ^ expkeys[i+j-nwords]
		}

		if nwords == 6 {
			for j := 4; j < 6; j++ {
				expkeys[i+j] = expkeys[i+j-1] ^ expkeys[i+j-nwords]
			}
		}

		if nwords == 8 {
			expkeys[i+4] = subWord(expkeys[i+3]) ^ expkeys[i+4-nwords]
			for j := 5; j < 8; j++ {
				expkeys[i+j] = expkeys[i+j-1] ^ expkeys[i+j-nwords]
			}
		}

		i += nwords
	}

	return expkeys
}

func rcon(i int) uint32 {
	return uint32(powx[i]) << 24
}

// rotWordLeft rotates the word n bytes to the left.
func rotWordLeft(input uint32, n uint) uint32 {
	return input>>(32-8*n) | input<<(8*n)
}

// rotWordRight rotates the word n bytes to the right.
func rotWordRight(input uint32, n uint) uint32 {
	return input<<(32-8*n) | input>>(8*n)
}

func subWord(input uint32) uint32 {
	return uint32(sbox0[input>>24&0xff])<<24 |
		uint32(sbox0[input>>16&0xff])<<16 |
		uint32(sbox0[input>>8&0xff])<<8 | uint32(sbox0[input&0xff])
}

func invSubWord(input uint32) uint32 {
	return uint32(sbox1[input>>24&0xff])<<24 |
		uint32(sbox1[input>>16&0xff])<<16 |
		uint32(sbox1[input>>8&0xff])<<8 | uint32(sbox1[input&0xff])
}
