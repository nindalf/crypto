package matasano

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"time"
)

//  a function that produces: AES-128-ECB(random-text-of-random-length || b || unknown-string, random-key)
func oraclehard(b []byte) []byte {
	plaintext := []byte("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	dec := make([]byte, (3*len(plaintext))/4)
	DecodeBase64(dec, plaintext)
	rand.Seed(time.Now().UnixNano())
	r := randbytes(rand.Intn(40))
	r = append(r, b...)
	r = append(r, dec...)
	r = PadPKCS7(r, 16)
	EncryptAESECB(r, rkey)
	return r
}

// BreakECBHard decrypts a ciphertext received from the oracle function (defined above)
// It does so by repeated calls to the oracle
// This solves http://cryptopals.com/sets/2/challenges/14/
func BreakECBHard() []byte {
	chosens, previous := genChosenCiphersHard()
	var decrypted bytes.Buffer
	for i := 0; i < 160; i += bsize {
		previous = decrypt16bytesHard(chosens, previous, i)
		fmt.Println(string(previous))
		decrypted.Write(previous) // reverse
	}
	return decrypted.Bytes()
}

func decrypt16bytesHard(chosens [][]byte, previous []byte, index int) []byte {
	decrypted := make([]byte, bsize)
	for i := bsize - 1; i >= 0; i-- {
		previous = previous[0 : len(previous)-1]
		l := len(chosens[i])
		dec := decryptbyteHard(chosens[i][l-index-32:l-index-16], previous)
		fmt.Print(dec)
		previous = append([]byte{dec}, previous...)
		decrypted[i] = dec
	}
	return decrypted
}

func decryptbyteHard(chosen, previous []byte) byte {
	previous = append([]byte{0}, previous...)
	temp := make([]byte, bsize)
	for i := 0; i < 255; i++ {
		copy(temp, previous)
		temp[0] = byte(i)
		temp, _ := encryptBlock(temp)
		if bytes.Equal(temp, chosen) {
			return byte(i)
		}
	}
	return 0
}

// generates chosen ciphertexts and the last decrypted block
func genChosenCiphersHard() ([][]byte, []byte) {
	chosens := make([][]byte, 0, bsize)
	existing := make(map[string]int)
	chosen := make([]byte, 48)
	var i int
	for len(chosens) != bsize {
		b := oraclehard(chosen)
		lastblock := string(b[len(b)-16 : len(b)])
		if _, ok := existing[lastblock]; ok == false {
			cutoff := getSimilarityCutoff(b)
			chosens = append(chosens, b[cutoff:len(b)])
			existing[lastblock] = i
			i++
		}
	}
	orderedChosens := make([][]byte, bsize)
	guessed, temp := make([]byte, 0, 16), make([]byte, 16)
	var err error
	for i := 15; i > 0; i-- {
		bc := make([]byte, 1, 16)
		bc = append(bc, guessed...)
		bc = PadPKCS7(bc, 16)
		for j := 0; j < 256; j++ {
			bc[0] = byte(j)
			copy(temp, bc)
			temp, err = encryptBlock(temp)
			if err != nil {
				fmt.Printf("Trouble encrypting %v, %s\n", bc, err)
			}

			if index, ok := existing[string(temp)]; ok {
				orderedChosens[i] = chosens[index]
				chosens[index] = make([]byte, 0)
				t := make([]byte, 1, 16)
				t[0] = byte(j)
				guessed = append(t, guessed...)
				break
			}
		}
	}
	for i := range chosens {
		if len(chosens[i]) > 0 {
			orderedChosens[0] = chosens[i]
		}
	}
	fmt.Println(guessed)
	return orderedChosens, guessed
}

func getSimilarityCutoff(b []byte) int {
	s := string(b)
	for i := 0; i < len(s)-32; i += 16 {
		if s[i:i+16] == s[i+16:i+32] {
			return i + 32
		}
	}
	return 0
}

// encrypts a 16 byte block under the uknown key
// its a little complicated to get a 16 byte block encrypted since we don't know where it will be
func encryptBlock(b []byte) ([]byte, error) {
	if len(b) != 16 {
		return b, errors.New("incorrect length")
	}
	pad := make([]byte, 32)
	block := make([]byte, 0, 80)
	block = append(block, pad...)
	block = append(block, b...)
	block = append(block, pad...)
	enc := oraclehard(block)
	// if the pads are on the 16-byte boundaries, they will generate 4 similar blocks
	for similarBlocks(string(enc)) < 4 {
		enc = oraclehard(block)
	}
	s := string(enc)
	for i := 0; i < len(s)-80; i += 16 {
		if s[i:i+16] == s[i+16:i+32] && s[i:i+16] != s[i+32:i+48] && s[i:i+16] == s[i+48:i+64] && s[i:i+16] == s[i+64:i+80] {
			return []byte(s[i+32 : i+48]), nil
		}
	}
	return b, errors.New("couldn't find the encrypted block")
}
