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
