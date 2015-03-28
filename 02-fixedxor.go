package matasano

func Xor(in1, in2 []byte) []byte {
	in1 = Hex2str(in1)
	in2 = Hex2str(in2)
	out := make([]byte, len(in1))

	for i := 0; i < len(in1); i++ {
		out[i] = in1[i] ^ in2[i]
	}

	return Str2hex(out)
}

func XorOne(in []byte, key byte) []byte {
	in = Hex2str(in)
	out := make([]byte, len(in))

	for i := 0; i < len(in); i++ {
		out[i] = in[i] ^ key
	}
	return out
}
