package matasano

import "errors"

// This pads an input array of bytes till it is a multiple of n bytes in length
// Described more here - https://en.wikipedia.org/wiki/Padding_%28cryptography%29#PKCS7
// This solves http://cryptopals.com/sets/2/challenges/9/
func padPKCS7(input []byte, n int) []byte {
	np := n - (len(input) % n)
	if np == 0 {
		np = n
	}
	padding := byte(np) - byte(0)
	for i := 0; i < np; i++ {
		input = append(input, padding)
	}
	return input
}

func stripPKCS7(input []byte) ([]byte, error) {
	l := len(input) - 1
	n := int(input[l])
	for i := l; i > l-n; i-- {
		if input[i] != input[l] {
			return input, errors.New("PKCS7 malformed")
		}
	}
	return input[0 : l-n+1], nil
}
