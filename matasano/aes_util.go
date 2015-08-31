package matasano

// pack moves bytes from src (bytes) to dst (state)
// It is assumed that len(src) % 4 == 0
// aes.go accepts AES input in the form of []uint32, where each AES block is 4 consecutive uint32s
// 4 uint32s correspond to 16 bytes in this manner:
// dst[0] = 0  4  8   12
// dst[1] = 1  5  9   13
// dst[2] = 2  6  10  14
// dst[3] = 3  7  11  15
func pack(dst []uint32, src []byte) {
	for i := 0; i < len(dst); i += 4 {
		for j := 0; j < 4; j++ {
			dst[i+j] = uint32(src[i*4+j])<<24 | uint32(src[(i+1)*4+j])<<16 | uint32(src[(i+2)*4+j])<<8 | uint32(src[(i+3)*4+j])
		}
	}
}

// unpack moves bytes from src (state) to dst (bytes)
// It is assumed that len(dst) % 4 == 0
func unpack(dst []byte, src []uint32) {
	for i := 0; i < len(src); i += 4 {
		for j := 0; j < 4; j++ {
			dst[(i+0)*4+j] = byte(src[i+j] >> 24)
			dst[(i+1)*4+j] = byte((src[i+j] >> 16) & 0xff)
			dst[(i+2)*4+j] = byte((src[i+j] >> 8) & 0xff)
			dst[(i+3)*4+j] = byte((src[i+j]) & 0xff)
		}
	}
}
