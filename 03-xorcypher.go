package matasano

var candidates = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
var freqletters = []byte("ETAOINSHRDLU etaoinshrdlu")

func DecryptXor(input []byte) []byte {
	var result []byte
	var currank int
	for _, l := range candidates {
		decrypted := XorOne(input, l)
		rank := getrank(decrypted)
		if currank < rank {
			currank = rank
			result = decrypted
		}
	}
	return result
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
