package matasano

const (
	minASCII = 32
	maxASCII = 126
)

var freqletters = []byte("ETAOINSHRDLU etaoinshrdlu")

// based on http://en.wikipedia.org/wiki/Letter_frequency
var letterfreq2 = map[byte]float64{'a': 8.167, 'A': 8.167,
	'b': 1.492, 'B': 1.492, 'c': 2.782, 'C': 2.782, 'd': 4.2583, 'D': 4.253,
	'e': 12.702, 'E': 12.702, 'f': 2.228, 'F': 2.228, 'g': 2.015, 'G': 2.015,
	'h': 6.094, 'H': 6.094, 'i': 6.966, 'I': 6.966, 'j': 0.153, 'J': 0.153,
	'k': 0.772, 'K': 0.772, 'l': 4.025, 'L': 4.025, 'm': 2.406, 'M': 2.406,
	'n': 6.749, 'N': 6.749, 'o': 7.507, 'O': 7.507, 'p': 1.929, 'P': 1.929,
	'q': 0.095, 'Q': 0.095, 'r': 5.987, 'R': 5.987, 's': 6.327, 'S': 6.327,
	't': 9.056, 'T': 9.056, 'u': 2.758, 'U': 2.758, 'v': 0.978, 'V': 0.978,
	'w': 2.360, 'W': 2.360, 'x': 0.150, 'X': 0.150, 'y': 1.974, 'Y': 1.974,
	'z': 0.074, 'Z': 0.074}

// modified version of the map above, to give lesser weight to etaoin
var letterfreq = map[byte]float64{'a': 3, 'A': 3,
	'b': 1.5, 'B': 1.5, 'c': 2.5, 'C': 2.5, 'd': 2.5, 'D': 2.5,
	'e': 3, 'E': 3, 'f': 2, 'F': 2, 'g': 2, 'G': 2,
	'h': 2.5, 'H': 2.5, 'i': 3, 'I': 3, 'j': 0.5, 'J': 0.5,
	'k': 1, 'K': 1, 'l': 2.5, 'L': 2.5, 'm': 2, 'M': 2,
	'n': 3, 'N': 3, 'o': 3, 'O': 3, 'p': 2, 'P': 2,
	'q': 0.1, 'Q': 0.1, 'r': 2.5, 'R': 2.5, 's': 2.5, 'S': 2.5,
	't': 3, 'T': 3, 'u': 2.5, 'U': 2.5, 'v': 1, 'V': 1,
	'w': 2, 'W': 2, 'x': 0.5, 'X': 0.5, 'y': 2, 'Y': 2,
	'z': 0.1, 'Z': 0.1}

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
		// rank += letterfreq[l]

		for j := range freqletters {
			if l == freqletters[j] {
				rank++
			}
		}
	}
	return rank
}
