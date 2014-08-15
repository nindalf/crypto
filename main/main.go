package main

import (
	"fmt"
	"github.com/nindalf/matasano"
)

// func main() {
// 	input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
// 	fmt.Println(matasano.DecryptXor(input))
// }

func main() {
	input1 := "1c0111001f010100061a024b53535009181c"
	input2 := "686974207468652062756c6c277320657965"
	// output "746865206169642064616127742070616179"
	fmt.Println(matasano.Xor(input1, input2))
}
