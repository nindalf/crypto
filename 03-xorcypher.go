package matasano

var candidates = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
var freqletters = []byte("ETAOINSHRDLU etaoinshrdlu")

// DecryptXor decrypts an array of bytes by XOR-ing it with all possible letters and choosing the
// array with the highest rank. Rank is equal to the number of letters the array has in common with freqletters
// It returns the decrypted byte array, the rank of that array and the key used to decrypt it
// This solves http://cryptopals.com/sets/1/challenges/3/
func DecryptXor(input []byte) ([]byte, int, byte) {
	var result []byte
	var currank int
	var rkey byte
	for _, key := range candidates {
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

func getrank(input []byte) int {
	var rank int
	for i := range input {
		for j := range freqletters {
			if input[i] == freqletters[j] {
				rank++
			}
		}
	}
	return rank
}
