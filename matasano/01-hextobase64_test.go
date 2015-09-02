package matasano

import "testing"

func TestEncodeBase64(t *testing.T) {
	inputs := []string{"pleasure.", "leasure.", "easure.", "asure.", "sure."}
	expected := []string{"cGxlYXN1cmUu", "bGVhc3VyZS4=", "ZWFzdXJlLg==", "YXN1cmUu", "c3VyZS4="}
	for i := range inputs {
		encoded := string(base64FromString([]byte(inputs[i])))
		if expected[i] != encoded {
			t.Fatalf("Input - %s\nExptected - %s\nActual - %s", inputs[i], expected[i], encoded)
		}
	}
}

func TestDecodeBase64(t *testing.T) {
	inputs := [][]byte{[]byte("cGxl\r\rYXN1cmUu"), []byte("bGVhc3\r\nVyZS4="),
		[]byte("Z\rWFzdXJlL\ng=="), []byte("YX\nN1c\nmUu"), []byte("c3\n\rVyZS4=")}
	expected := []string{"pleasure.", "leasure.", "easure.", "asure.", "sure."}
	for i, src := range inputs {
		dst := make([]byte, (len(src)/4)*3)
		n := DecodeBase64(dst, src)
		dst = dst[0:n]
		if string(dst) != expected[i] {
			t.Fatalf("Input - %s\nExpected - %s\nFound - %s", string(src), expected[i], string(dst))
		}
	}
}

func TestStringFromHex(t *testing.T) {
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	expected := "I'm killing your brain like a poisonous mushroom"
	actual := string(StringFromHex([]byte(input)))
	if expected != actual {
		t.Fatalf("Input - %s\nExptected - %s\nActual - %s", input, expected, actual)
	}
}

func TestBase64FromHex(t *testing.T) {
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	actual := string(Base64FromHex([]byte(input)))
	if expected != actual {
		t.Fatalf("Input - %s\nExptected - %s\nActual - %s", input, expected, actual)
	}
}
