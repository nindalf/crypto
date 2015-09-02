package matasano

// ValidatePKCS7 checks if the padding on a slice of bytes is PKCS7
// If the padding isn't valid, the function panics
// This solves http://cryptopals.com/sets/2/challenges/15
func ValidatePKCS7(b []byte) {
	_, err := StripPKCS7(b)
	if err != nil {
		panic("Not valid padding")
	}
}
