package matasano

import "bytes"

var base64vals = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
var hexvals = []byte("0123456789abcdef")

// Hex2base64 converts a hex string to a base64 encoded string
// This solves http://cryptopals.com/sets/1/challenges/1/
func Hex2base64(hex []byte) []byte {
	hex = hex2str(hex)
	return str2base64(hex)
}

func hex2str(hex []byte) []byte {
	convert := func(hex []byte) byte {
		var sum int
		sum += bytes.Index(hexvals, hex[0:1]) * 16
		sum += bytes.Index(hexvals, hex[1:2]) * 1
		return byte(sum)
	}
	var b bytes.Buffer
	for i := 0; i < len(hex); {
		b.WriteByte(convert(hex[i : i+2]))
		i += 2
	}
	return b.Bytes()
}

func str2hex(str []byte) []byte {
	convert := func(b byte) []byte {
		out := make([]byte, 2)
		out[1] = hexvals[b/16]
		out[0] = hexvals[b%16]
		return out
	}
	var b bytes.Buffer
	for i := 0; i < len(str); i++ {
		hex := convert(str[i])
		b.WriteByte(hex[1])
		b.WriteByte(hex[0])
	}
	return b.Bytes()
}

func str2base64(b []byte) []byte {
	dst := make([]byte, maxEncodeLength(b))
	EncodeBase64(dst, b)
	return dst
}

func maxEncodeLength(b []byte) int {
	n := len(b)
	if n%3 == 0 {
		return (n / 3) * 4
	}
	return ((n / 3) + 1) * 4
}

// EncodeBase64 encodes a string to base64
// This is my implementation, which is not that bad compared to the std lib implementation below
func EncodeBase64(dst, src []byte) {
	var i, j int
	for i+2 < len(src) {
		encode4Base64Bytes(dst[j:j+4], src[i:i+3])
		i += 3
		j += 4
	}
	switch len(src[i:len(src)]) {
	case 2:
		src = pad(src, 1)
		encode4Base64Bytes(dst[j:j+4], src[i:i+3])
		dst[j+3] = 64 // equality symbol
	case 1:
		src = pad(src, 2)
		encode4Base64Bytes(dst[j:j+4], src[i:i+3])
		dst[j+3] = 64
		dst[j+2] = 64
	}
	for i := 0; i < len(dst); i++ {
		dst[i] = base64vals[dst[i]]
	}
}

func encode4Base64Bytes(dst, src []byte) {
	dst[0] = src[0] >> 2
	dst[1] = ((src[0] & ((1 << 2) - 1)) << 4) | (src[1] >> 4)
	dst[2] = ((src[1] & ((1 << 4) - 1)) << 2) | src[2]>>6
	dst[3] = (src[2] & ((1 << 6) - 1))
}

func pad(b []byte, n int) []byte {
	t := make([]byte, n)
	for _, l := range t {
		b = append(b, l)
	}
	return b
}

// From the go std lib - http://golang.org/src/encoding/base64/base64.go
// I made a minor modification - removing encoder and using base64vals instead

// Encode encodes src using the encoding enc, writing
// EncodedLen(len(src)) bytes to dst.
//
// The encoding pads the output to a multiple of 4 bytes,
// so Encode is not appropriate for use on individual blocks
// of a large data stream.  Use NewEncoder() instead.
func Encode(dst, src []byte) {
	if len(src) == 0 {
		return
	}

	for len(src) > 0 {
		var b0, b1, b2, b3 byte

		// Unpack 4x 6-bit source blocks into a 4 byte
		// destination quantum
		switch len(src) {
		default:
			b3 = src[2] & 0x3F
			b2 = src[2] >> 6
			fallthrough
		case 2:
			b2 |= (src[1] << 2) & 0x3F
			b1 = src[1] >> 4
			fallthrough
		case 1:
			b1 |= (src[0] << 4) & 0x3F
			b0 = src[0] >> 2
		}

		// Encode 6-bit blocks using the base64 alphabet
		dst[0] = base64vals[b0]
		dst[1] = base64vals[b1]
		dst[2] = base64vals[b2]
		dst[3] = base64vals[b3]

		// Pad the final quantum
		if len(src) < 3 {
			dst[3] = '='
			if len(src) < 2 {
				dst[2] = '='
			}
			break
		}

		src = src[3:]
		dst = dst[4:]
	}
}
