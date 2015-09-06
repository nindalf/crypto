package matasano

import "crypto/aes"

// DetectAESECB detects which line is likely to be encoded by AES in ECB mode
// This solves http://cryptopals.com/sets/1/challenges/8/
func DetectAESECB(lines []string) string {
	var result string
	var blockScore int
	for _, line := range lines {
		if similarBlocks(line) > blockScore {
			result = line
			blockScore = similarBlocks(line)
		}
	}
	return result
}

func similarBlocks(line string) int {
	var score int
	blocks := make(map[string]int)
	for i := 0; i < len(line); i += aes.BlockSize {
		cur := line[i : i+aes.BlockSize]
		blocks[cur] = blocks[cur] + 1
	}
	for _, v := range blocks {
		if v > 1 {
			score += v
		}
	}
	return score
}
