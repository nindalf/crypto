package matasano

// FindXORLine finds line that has been XOR-ed with some byte
// This solves http://cryptopals.com/sets/1/challenges/4/
func FindXORLine(lines [][]byte) ([]byte, []byte, byte) {
	var result, line []byte
	var rkey byte
	var currank float64
	for _, l := range lines {
		decrypted, rank, key := BreakSingleXor(stringFromHex(l))
		if currank < rank {
			currank = rank
			result = decrypted
			line = l
			rkey = key
		}
	}
	return result, line, rkey
}
