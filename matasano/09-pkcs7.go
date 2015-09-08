package matasano

import "errors"

var errPaddingMalformed = errors.New("PKCS7 malformed")

// PadPKCS7 pads an input array of bytes till it is a multiple of n bytes in length
// Described more here - https://en.wikipedia.org/wiki/Padding_%28cryptography%29#PKCS7
// This solves http://cryptopals.com/sets/2/challenges/9/
func PadPKCS7(input []byte, n int) []byte {
	np := n - (len(input) % n)
	padding := byte(np) - byte(0)

	pbytes := make([]byte, np)
	for i := range pbytes {
		pbytes[i] = padding
	}

	input = append(input, pbytes...)
	return input
}

// StripPKCS7 removes the PKCS7 padding from a slice of bytes
func StripPKCS7(input []byte) ([]byte, error) {
	l := len(input) - 1
	n := int(input[l])
	if n < 1 {
		return input, errPaddingMalformed
	}

	for i := l; i > l-n; i-- {
		if input[i] != input[l] {
			return input, errPaddingMalformed
		}
	}

	return input[0 : l-n+1], nil
}
