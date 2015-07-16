package matasano

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
