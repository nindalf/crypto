package matasano

import (
	"bytes"
	"io/ioutil"
)

func FindLine(filepath string) ([]byte, []byte) {
	var result, line []byte

	b, err := ioutil.ReadFile(filepath)
	if err != nil {
		return result, line
	}
	lines := bytes.Split(b, []byte("\n"))
	var currank int
	for _, l := range lines {
		decrypted, rank := DecryptXor(l)
		if currank < rank {
			currank = rank
			result = decrypted
			line = l
		}
	}
	return result, line
}
