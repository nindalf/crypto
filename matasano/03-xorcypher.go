package matasano

const (
	minASCII = 32
	maxASCII = 126
)

// approximate frequencies of letters used in the english language
// ETAOIN = 3, SHRDLU = 2.5, FGPWY = 2, B = 1.5, KV = 1.0, JX = 0.5, QZ = 0.1
// based on http://en.wikipedia.org/wiki/Letter_frequency
var letterfreq = map[byte]float64{'a': 3.0, 'A': 3.0,
	'b': 1.5, 'B': 1.5, 'c': 2.5, 'C': 2.5, 'd': 2.5, 'D': 2.5,
	'e': 3.0, 'E': 3.0, 'f': 2.0, 'F': 2.0, 'g': 2.0, 'G': 2.0,
	'h': 2.5, 'H': 2.5, 'i': 3.0, 'I': 3.0, 'j': 0.5, 'J': 0.5,
	'k': 1.0, 'K': 1.0, 'l': 2.5, 'L': 2.5, 'm': 2.0, 'M': 2.0,
	'n': 3.0, 'N': 3.0, 'o': 3.0, 'O': 3.0, 'p': 2.0, 'P': 2.0,
	'q': 0.1, 'Q': 0.1, 'r': 2.5, 'R': 2.5, 's': 2.5, 'S': 2.5,
	't': 3.0, 'T': 3.0, 'u': 2.5, 'U': 2.5, 'v': 1.0, 'V': 1.0,
	'w': 2.0, 'W': 2.0, 'x': 0.5, 'X': 0.5, 'y': 2.0, 'Y': 2.0,
	'z': 0.1, 'Z': 0.1, ' ': 3}

// DecryptXor decrypts an array of bytes by XOR-ing it with all possible letters and choosing the
// array with the highest rank.
// It returns the decrypted byte array, the rank of that array and the key used to decrypt it
// This solves http://cryptopals.com/sets/1/challenges/3/
func DecryptXor(input []byte) ([]byte, float64, byte) {
	var result []byte
	var currank float64
	var rkey byte
	for i := minASCII; i <= maxASCII; i++ {
		key := byte(i)
		decrypted := XorOne(input, key)
		rank := getrank(decrypted)
		if currank < rank {
			currank = rank
			result = decrypted
			rkey = key
		}
	}
	return result, currank, rkey
}

func getrank(input []byte) float64 {
	var rank float64
	for _, l := range input {
		rank += letterfreq[l]
	}
	return rank
}
