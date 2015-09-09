package matasano

import "testing"

func TestCBCPaddingOracle(t *testing.T) {
	for _, s := range plaintexts17 {
		encrypted, iv := encrypt17(s)

		plaintext := CBCPaddingOracle(encrypted, iv)
		plaintext, err := StripPKCS7(plaintext)
		if err != nil || string(plaintext) != s {
			t.Fatalf("Expected - %v\nActual - %v", []byte(s), plaintext)
		}
	}
}

// func TestCBCPaddingOracle2(t *testing.T) {
// 	iv := make([]byte, 16)
// 	rand.Read(iv)
// 	cbcEnc.(ivSetter).SetIV(iv)
//
// 	dst := make([]byte, 16)
// 	src := make([]byte, 16)
// 	rand.Read(src)
//
// 	for i := 15; i > 0; i-- {
// 		src = src[:i]
// 		src = PadPKCS7(src, 16)
//
// 		cbcEnc.CryptBlocks(dst, src)
//
// 		actual := CBCPaddingOracle(dst, iv)
// 		if !bytes.Equal(actual, src) {
// 			t.Fatalf("Expected - %v\nActual - %v", src, actual)
// 		}
// 	}
// }
