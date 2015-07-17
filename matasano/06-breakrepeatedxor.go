package matasano

import "bytes"

const (
	minKeySize = 2
	maxKeySize = 40
)

// DecryptRepeatedXOR decrypts ciphertext encrypted with repeating-key XOR
// This solves http://cryptopals.com/sets/1/challenges/6/
func DecryptRepeatedXOR(b []byte) (string, string) {
	ksize := keysize(b)
	buffers := make([]bytes.Buffer, ksize)
	for i := 0; i < len(b)-ksize; {
		for j := 0; j < len(buffers); j++ {
			buffers[j].WriteByte(b[i+j])
		}
		i += ksize
	}
	var key bytes.Buffer
	for i := 0; i < len(buffers); i++ {
		_, _, keybyte := DecryptXor(buffers[i].Bytes())
		key.WriteByte(keybyte)
	}

	return key.String(), string(decryptRepeatedXor(b, key.Bytes()))
}

func keysize(p []byte) int {
	var curdistance, curkeysize int
	curdistance = (1 << 32) - 1
	for i := minKeySize; i <= maxKeySize; i++ {
		distance := 0
		for j := 0; j < len(p)-i*2; {
			distance += hammingdistance(p[j:j+i], p[j+i:j+2*i])
			j += i
		}
		if curdistance > distance {
			curdistance = distance
			curkeysize = i
		}
	}

	return curkeysize
}

// hammingdistance finds the hamming distance between two byte arrays
// hammingdistance(i, j) = hammingweight(i^j)
// Methods to find weight - http://en.wikipedia.org/wiki/Hamming_weight
// Super convoluted and efficient way to find weight - http://stackoverflow.com/a/109025/1109785
func hammingdistance(p, q []byte) int {
	numbitset := func(b byte) int {
		var count int
		for b != 0 {
			b &= b - 1
			count++
		}
		return count
	}

	var distance int
	for i := 0; i < len(p); i++ {
		t := p[i] ^ q[i]
		distance += numbitset(t)
	}
	return distance
}
