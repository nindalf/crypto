package matasano

import (
	"io/ioutil"
	"strings"
)

// DetectAESECB detects which line is likely to be encoded by AES in ECB mode
// This solves http://cryptopals.com/sets/1/challenges/3/
func DetectAESECB(filepath string) (string, error) {
	lines, err := ioutil.ReadFile(filepath)
	if err != nil {
		return "", err
	}
	var result string
	var blockScore int
	for _, line := range strings.Split(string(lines), "\n") {
		if similarBlocks(line) > blockScore {
			result = line
			blockScore = similarBlocks(line)
		}
	}
	return result, nil
}

func similarBlocks(line string) int {
	var score int
	blocks := make(map[string]int)
	for i := 0; i < len(line); {
		cur := line[i : i+32]
		i += 32
		blocks[cur] = blocks[cur] + 1
	}
	for _, v := range blocks {
		if v > 1 {
			score += v
		}
	}
	return score
}
