package matasano

import (
	"fmt"
)

const attempts = "0123456789abcdef"

func tempstr(k uint8, length int) string {
	out := ""
	for i := 0; i < length; i++ {
		out = out + string(k)
	}
	return out
}
func DecryptXor(input string) string {
	for i := 0; i < len(attempts); i++ {
		fmt.Println(Xor(input, tempstr(attempts[i], len(input))))
	}
	return Xor(input, input)
}

// func main() {
// 	input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
// 	fmt.Println(DecryptXor(input))
// }
