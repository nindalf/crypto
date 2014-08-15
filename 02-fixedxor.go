package main

import (
	"fmt"
	"strconv"
)

func runetoint(k uint8) int {
	if k >= '0' && k <= '9' {
		return int(k - '0')
	}
	if k >= 'a' && k <= 'f' {
		return int(k-'a') + 10
	}
	return 0
}

func Xor(in1, in2 string) string {
	out := ""
	var temp1, temp2 int
	for i := 0; i < len(in1); i++ {
		temp1 = runetoint(in1[i])
		temp2 = runetoint(in2[i])
		out = out + strconv.Itoa(temp1^temp2)
	}
	return out
}

func main() {
	input1 := "1c0111001f010100061a024b53535009181c"
	input2 := "686974207468652062756c6c277320657965"
	// output "746865206169642064616127742070616179"
	fmt.Println(Xor(input1, input2))
}
