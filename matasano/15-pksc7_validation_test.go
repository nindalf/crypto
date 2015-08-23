package matasano

import "testing"

func TestValidatePKCS7(t *testing.T) {
	input := []string{"ICE ICE BABY\x04\x04\x04\x04", "ICE ICE BABY\x05\x05\x05\x05", "ICE ICE BABY\x01\x02\x03\x04"}
	expected := []bool{false, true, true}
	for i := range input {
		safelyCheck(t, input[i], expected[i])
	}
}

func safelyCheck(t *testing.T, input string, expected bool) {
	defer func() {
		err := recover()
		if err != nil && expected == false {
			t.Fatalf("Input - %s\nExpected to panic - %v", input, expected)
		}
		if err == nil && expected == true {
			t.Fatalf("Input - %s\nExpected to panic - %v", input, expected)
		}
	}()
	ValidatePKCS7([]byte(input))
}
