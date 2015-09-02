package matasano

import (
	"fmt"
	"testing"
)

func TestCBCPaddingOracle(t *testing.T) {
	b, iv := encrypt17()
	p := CBCPaddingOracle(b, iv)
	fmt.Println(string(p))
}