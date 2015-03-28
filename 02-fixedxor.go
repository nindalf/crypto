package matasano

// Xor takes two equal-length buffers and produces their XOR combination.
// This solves http://cryptopals.com/sets/1/challenges/2/
func Xor(in1, in2 []byte) []byte {
	in1 = hex2str(in1)
	in2 = hex2str(in2)
	out := make([]byte, len(in1))

	for i := 0; i < len(in1); i++ {
		out[i] = in1[i] ^ in2[i]
	}

	return str2hex(out)
}

// Xor takes a buffer and XORs it with a single byte
// This function is used in subsequent challenges
func XorOne(in []byte, key byte) []byte {
	in = hex2str(in)
	out := make([]byte, len(in))

	for i := 0; i < len(in); i++ {
		out[i] = in[i] ^ key
	}
	return out
}
