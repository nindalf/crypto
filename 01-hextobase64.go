package main

import (
	"encoding/base64"
	"fmt"
)

func hex2base64(hex string) string {
	src := []byte(hex)
	enc := base64.StdEncoding.EncodeToString(src)
	return enc
}

func main() {
	fmt.Println(hex2base64("Man is distinguished, not only by his reason, but by this singular passion from"))
}
