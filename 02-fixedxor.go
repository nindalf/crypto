package matasano

import (
	"strconv"
)

func runetoint(k uint8) int {
	if k >= '0' && k <= '9' {
		return int(k - '0')
	} else {
		return int(k-'a') + 10
	}
}

func inttostr(i int) string {
	if i >= 0 && i <= 9 {
		return strconv.Itoa(i)
	} else {
		return string(rune(i-10) + 'a')
	}
}

func Xor(in1, in2 string) string {
	out := ""
	var temp1, temp2 int
	for i := 0; i < len(in1); i++ {
		temp1 = runetoint(in1[i])
		temp2 = runetoint(in2[i])
		out = out + inttostr(temp1^temp2)
	}
	return out
}

// func main() {
// 	input1 := "1c0111001f010100061a024b53535009181c"
// 	input2 := "686974207468652062756c6c277320657965"
// 	// output "746865206b696420646f6e277420706c6179"
// 	fmt.Println(Xor(input1, input2))
// }
