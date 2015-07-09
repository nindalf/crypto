package matasano

import "bytes"

var base64enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
var base64dec = map[byte]byte{'a': 26, 'A': 0,
	'b': 27, 'B': 1, 'c': 28, 'C': 2, 'd': 29, 'D': 3,
	'e': 30, 'E': 4, 'f': 31, 'F': 5, 'g': 32, 'G': 6,
	'h': 33, 'H': 7, 'i': 34, 'I': 8, 'j': 35, 'J': 9,
	'k': 36, 'K': 10, 'l': 37, 'L': 11, 'm': 38, 'M': 12,
	'n': 39, 'N': 13, 'o': 40, 'O': 14, 'p': 41, 'P': 15,
	'q': 42, 'Q': 16, 'r': 43, 'R': 17, 's': 44, 'S': 18,
	't': 45, 'T': 19, 'u': 46, 'U': 20, 'v': 47, 'V': 21,
	'w': 48, 'W': 22, 'x': 49, 'X': 23, 'y': 50, 'Y': 24,
	'z': 51, 'Z': 25, '0': 52, '1': 53, '2': 54, '3': 55,
	'4': 56, '5': 57, '6': 58, '7': 59, '8': 60, '9': 61,
	'+': 62, '/': 63, '=': 0}

var hexvals = []byte("0123456789abcdef")

// Base64FromHex converts a hex string to a base64 encoded string
// This solves http://cryptopals.com/sets/1/challenges/1/
func Base64FromHex(hex []byte) []byte {
	return base64FromString(stringFromHex(hex))
}

func stringFromHex(hex []byte) []byte {
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

func hexFromString(str []byte) []byte {
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

func base64FromString(b []byte) []byte {
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
		dst[i] = base64enc[dst[i]]
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

// copied from http://golang.org/src/encoding/base64/base64.go#L54
var removeNewlinesMapper = func(r rune) rune {
	if r == '\r' || r == '\n' {
		return -1
	}
	return r
}

// DecodeBase64 decodes a base64 encoded string
// Skips all the error checking done in the stdlib implementation.
// It will panic on mangled input
func DecodeBase64(dst, src []byte) int {
	src = bytes.Map(removeNewlinesMapper, src)
	var written int
	for len(src) > 0 {
		var b0, b1, b2 byte

		b0 = base64dec[src[0]] << 2

		b0 |= base64dec[src[1]] >> 4
		b1 = base64dec[src[1]] << 4

		b1 |= base64dec[src[2]] >> 2
		b2 = base64dec[src[2]] << 6

		b2 |= base64dec[src[3]]

		dst[0] = b0
		dst[1] = b1
		dst[2] = b2

		src = src[4:]
		dst = dst[3:]
		written += 3
		if len(src) == 4 {
			if src[3] == '=' {
				written--
			}
			if src[2] == '=' {
				written--
			}
		}
	}
	return written
}

// From the go std lib - http://golang.org/src/encoding/base64/base64.go#L71
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
		dst[0] = base64enc[b0]
		dst[1] = base64enc[b1]
		dst[2] = base64enc[b2]
		dst[3] = base64enc[b3]

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
