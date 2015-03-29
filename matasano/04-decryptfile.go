package matasano

import (
	"bytes"
	"io/ioutil"
)

// FindLine searches the given file for a line that has been XOR-ed with some digit
// This solves http://cryptopals.com/sets/1/challenges/4/
func FindLine(filepath string) ([]byte, []byte, byte) {
	var result, line []byte
	var rkey byte

	b, err := ioutil.ReadFile(filepath)
	if err != nil {
		return result, line, rkey
	}
	lines := bytes.Split(b, []byte("\n"))
	var currank float64
	for _, l := range lines {
		decrypted, rank, key := DecryptXor(hex2str(l))
		if currank < rank {
			currank = rank
			result = decrypted
			line = l
			rkey = key
		}
	}
	return result, line, rkey
}
