package aes

// pack moves bytes from src (16 bytes) to dst ([]uint32 of len 4)
// 4 uint32s correspond to 16 bytes in this manner:
// dst[0] = 0  4  8   12
// dst[1] = 1  5  9   13
// dst[2] = 2  6  10  14
// dst[3] = 3  7  11  15
func pack(dst []uint32, src []byte) {
	for i := 0; i < 4; i++ {
		dst[i] = uint32(src[i])<<24 | uint32(src[4+i])<<16 | uint32(src[8+i])<<8 | uint32(src[12+i])
	}
}

// unpack moves bytes from src (state) to dst (bytes)
// It is assumed that len(dst) >= 16
func unpack(dst []byte, src []uint32) {
	for i := 0; i < 4; i++ {
		dst[i] = byte(src[i] >> 24)
		dst[4+i] = byte((src[i] >> 16) & 0xff)
		dst[8+i] = byte((src[i] >> 8) & 0xff)
		dst[12+i] = byte((src[i]) & 0xff)
	}
}
