package matasano

import (
	"fmt"
	"testing"
)

// func TestDecryptAES(t *testing.T) {
// 	DecryptAES("07-data.txt")
// }

func TestKeyExpansion(t *testing.T) {
	key := "YELLOW SUBMARINE"
	// keyExpansion([]byte(key))
	expkeys := keyExpansion([]byte(key))
	fmt.Println(len(expkeys))
	for i := range expkeys {
		fmt.Println(expkeys[i])
	}
}

/*
key expansion of "YELLOW SUBMARINE" seems to be
[89 69 76 76 79 87 32 83 85 66 77 65 82 73 78 69]
[91 126 99 207 20 41 67 156 65 107 14 221 19 34 64 152]
[34 237 106 14 54 196 41 146 119 175 39 79 100 141 103 215]
[105 176 239 138 95 116 198 24 40 219 225 87 76 86 134 128]
[80 1 171 209 15 117 109 201 39 174 140 158 107 248 10 30]
[15 64 204 218 0 53 161 19 39 155 45 141 76 99 39 147]
[102 187 0 135 102 142 161 148 65 21 140 25 13 118 171 138]
[49 131 98 83 87 13 195 199 22 24 79 222 27 110 228 84]
[133 28 11 78 210 17 200 137 196 9 135 87 223 103 99 3]
[45 153 240 21 255 136 56 156 59 129 191 203 228 230 220 200]
[40 23 118 10 215 159 78 150 236 30 241 93 8 248 45 149]
*/
