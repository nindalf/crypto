Implementing AES
===

The Advanced Encryption Standard is the most widely used encryption algorithm today. Its fast and secure but also easy to understand and implement.

If you're interested in learning about AES, look at this comic - [A Stick Figure Guide to the Advanced Encryption Standard](http://www.moserware.com/2009/09/stick-figure-guide-to-advanced.html). He splits his comic into 4 Acts:

1. brief history of crypto
2. crypto basics
3. implementation
4. math.

He did a great job with all 4 parts, but I thought elaborating on the implementation would be helpful. In this post, I will only assume you've read Acts 2 and 3 and signed the foot-shooting-prevention agreement.

<center>![Agreement](http://i.imgur.com/bPZzTwsl.png)</center>

---

### AES Encryption

The implementation of AES involves doing a set of simple operations repeatedly. Each repetition is called a "round". Depending on the size of the key (128, 192 or 256 bit), the input (block of 16 bytes) goes through 10, 12 or 14 rounds. In applying the 2 Big Ideas - Diffusion and Confusion, AES makes sure that each bit in the 16 byte block depends on every bit in the same block from 2 rounds previously. That's quite the achievement, so lets speak about the operations in detail.

Each round consists of 4 steps

1. applying a key - `addRoundKey()`
2. substituting bytes - `subBytes()`
3. shifting rows - `shiftRows()`
4. mixing columns - `mixColumns()`

Decryption involves the inverse of these steps, in reverse order

1. inverse-mixing columns - `invMixColumns()`
2. inverse-shifting rows - `invShiftRows()`
3. inverse-substituting bytes - `invSubBytes()`
4. applying a key - `addRoundKey()`

Have a look at the `encrypt` function below, implemented in Go (Go has a C-like syntax)

```
func encrypt(state, expkey []uint32, rounds int) {
	keyi := 0
	addRoundKey(state, expkey[keyi:keyi+4])
	keyi += 4
	for i := 0; i < rounds; i++ {
		subBytes(state)
		shiftRows(state)
		mixColumns(state)
		addRoundKey(state, expkey[keyi:keyi+4])
		keyi += 4
	}
	subBytes(state)
	shiftRows(state)
	addRoundKey(state, expkey[keyi:keyi+4])
}
```

Notes on the implementation:

* The 16-byte block, called state is represented as a slice of 4 4-byte unsigned integers. The 4-byte unsigned int is also referred to as a "word".
* The expanded key is based on the original key. Its 16*(rounds+1) bytes in length.

---

### Step 1: subBytes and invSubBytes

All the 4 operations are invertible. If you took any random 16-byte state and applied any operation and its inverse, you'd get back the original state. This is how decryption is a simple mirror of the encryption process.

In `subBytes` each of the 16 bytes is replaced by a byte from the S-box (a lookup table). The code would look like:

```
input[i] = sbox[input[i]] // i = 0, 1, ..., 15
```

For `invSubBytes`, only the lookup table is changed. The code is `input[i] = invsbox[input[i]]`. The values for both lookup tables can be found on the [wiki page](https://en.wikipedia.org/wiki/Rijndael_S-box). If this step appears really simple, its because it is. Nevertheless, I'd suggest writing a test to check if its working correctly.

```
input := []uint32{0x8e9ff1c6, 0x4ddce1c7, 0xa158d1c8, 0xbc9dc1c9}
expected := []uint32{0x19dba1b4, 0xe386f8c6, 0x326a3ee8, 0x655e78dd}
```

Another useful test would be to apply `subBytes` and `invSubBytes` on 16 random bytes and check if you get back the original.

---

### Step 2: shiftRows and invShiftRows

In `shiftRows`, the rows are shifted left. The top row is left untouched, the second row by 1 byte, the third row by 2 bytes, the fourth row by 3 bytes. As depicted below

![shiftrows](https://upload.wikimedia.org/wikipedia/commons/6/66/AES-ShiftRows.svg)

```
func shiftRows(state []uint32) {
	for i := 1; i < 4; i++ {
		// rotate word left by specified number of bytes
		state[i] = rotWordLeft(state[i], i)
	}
}
```

To test if `shiftRows` working correctly, use this input

```
input := []uint32{
		0x8e9f01c6,
		0x4ddc01c6,
		0xa15801c6,
		0xbc9d01c6}
expected := []uint32{
		0x8e9f01c6,
		0xdc01c64d,
		0x01c6a158,
		0xc6bc9d01}
```

`invShiftRows` is the inverse operation. The top row is left untouched and the next 3 rows are shifted right by 1, 2, 3 bytes. Again, I'd recommend writing a test to ensure that applying both `shiftRows` and `invShiftRows` to random bytes returns the original.

---

### Step 3: mixColumns and invMixColumns

This step is slightly complicated, compared to the other 3. The state is operated on column-wise. Each byte of the column is replaced based on an operation. As you'd expect, in `invMixColumns` the 4 bytes are replaced by the 4 original ones.

![mixcols](https://upload.wikimedia.org/wikipedia/commons/7/76/AES-MixColumns.svg)

Speaking about the operation itself, it involves multiplication and addition in the Galois field. That sounded arcane to me, until I realised that I can get the results of multiplication via a lookup table and addition is just bit-wise XOR.

```
// a0-3 represent the bytes of a column from top to bottom
// r0-3 are the transformed bytes

func calcMixCols(a0, a1, a2, a3 byte) (r0, r1, r2, r3 byte) {
	// r0 = 2*a0 + 3*a1 + a2   + a3
	// r1 = a0   + 2*a1 + 3*a2 + a3
	// r2 = a0   + a1   + 2*a2 + 3*a3
	// r3 = 3*a0 + a1   + a2   + 2*a3
  r0 = gMulBy2[a0] ^ gMulBy3[a1] ^  a2  ^  a3
  r1 = a0          ^ gMulBy2[a1] ^ gMulBy3[a2] ^ a3
  r2 = a0  ^  a1   ^ gMulBy2[a2] ^ gMulBy3[a3]
  r3 = gMulBy3[a0] ^  a1  ^  a2  ^ gMulBy2[a3]
  return
}

func calcInvMixCols(a0, a1, a2, a3 byte) (r0, r1, r2, r3 byte) {
	// r0 = 14*a0 + 11*a1 + 13*a2 +  9*a3
	// r1 =  9*a0 + 14*a1 + 11*a2 + 13*a3
	// r2 = 13*a0 +  9*a1 + 14*a2 + 11*a3
	// r3 = 11*a0 + 13*a1 +  9*a2 + 14*a3
  r0 = gMulBy14[a0]^gMulBy11[a1]^gMulBy13[a2]^gMulBy9[a3]  
  r1 = gMulBy9[a0] ^gMulBy14[a1]^gMulBy11[a2]^gMulBy13[a3]
  r2 = gMulBy13[a0]^gMulBy9[a1] ^gMulBy14[a2]^gMulBy11[a3]
  r3 = gMulBy11[a0]^gMulBy13[a1]^gMulBy9[a2] ^gMulBy14[a3]
  return
}
```

Each of the `gMulBy` lookup tables are 256 bytes in size. (You can find them [here](https://en.wikipedia.org/wiki/Rijndael_mix_columns#Galois_Multiplication_lookup_tables))

```
input := []uint32{
    0xdbf201c6,
    0x130a01c6,
    0x532201c6,
    0x455c01c6}
expected := []uint32{
    0x8e9f01c6,
    0x4ddc01c6,
    0xa15801c6,
    0xbc9d01c6}
```

For `invMixColumns`, the test vectors are simply reversed. As with the other steps, it's a good idea to check if your `mixColumns` and `invMixColumns` invert each other.

I'm not going to explain Galois field arithmetic here for 2 reasons: I'd prefer to keep this post short, and its not necessary to know exactly how it works while implementing AES. I do recommend reading [this book](http://www.amazon.com/Design-RijndaeL-Encryption-Information-Cryptography/dp/3540425802) by the creators of AES if you're interested in that or other interesting topics like cryptanalysis of AES.

---

### Step 4: addRoundKey

The simplest of all the steps. A bit-wise XOR between the 16-byte state and the appropriate 16-bytes of the expanded key.

```
func addRoundKey(state, key []uint32) {
	for i := 0; i < 4; i++ {
		state[i] = state[i] ^ key[i]
	}
}
```

As you probably know, XOR-ing any input with the same key twice returns the original input. That's why we use the same operation with the same key in both encryption and decryption.

---

### Step 0: Key Expansion

I mentioned previously that the expanded key is based on the 16-byte key and its 16*(rounds+1) bytes in length. Thus, a different 16-bytes is used for each  call to `addRoundKey`

---

### Potential gotcha

Be careful of how you fill the state matrix with your 16 bytes of input.

```
// wrong
 0  1  2  3
 4  5  6  7
 8  9 10 11
12 13 14 15

// correct
 0  4  8 12
 1  5  9 13
 2  6 10 14
 3  7 11 15
```

---

### Congrats!

You just implemented AES. Try decrypting the file [here](http://cryptopals.com/sets/1/challenges/7/) to see if you got it right :)

If you haven't yet managed it, you could check out the [FIPS-197 Document](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf) which elaborates on each step.

---

### My implementation

You can find my implementation here:

* [aes.go](https://github.com/nindalf/crypto/blob/master/aes/aes.go) - `encrypt()`, `decrypt()` and all helper functions.
* [aes_test.go](https://github.com/nindalf/crypto/blob/master/aes/aes_test.go) - test vectors for each step.
* [const.go](https://github.com/nindalf/crypto/blob/master/aes/const.go) - S-boxes and the Galois-field multiplication lookup tables.

The caveats mentioned in the foot-shooting-prevention agreement apply to my code as well. The linked code is useful for learning about AES, but is not secure and should not be used to encrypt anything important.

---

### Advanced implementation

The creators of AES designed the algorithm in such a way that implementations could make a trade-off between speed and code size. There are 4 possible levels, increasing in size and speed:

* 0kB - no lookup tables, all steps are calculated, including substitution.
* 256 bytes x 2 - s-box and inverse-s-box are stored as lookup tables.
* 4kB x 2  - the Galois field multiplication tables are stored. (Approach taken by my impl.)
* 24kB x2 - The entire round (`subBytes`, `shiftRows` and `mixColumns`) are replaced by a lookup table. The only operation left is `addRoundKey`.

The last is the fastest possible software implementation. Such an implementation can be found in the Go standard library [here](http://golang.org/src/crypto/aes/block.go). If the CPU's cache is large enough to accommodate the entire table, it will be really fast.

Hardware implementations are even faster. Intel and AMD introduced CPU instructions called [AES-NI](https://en.wikipedia.org/wiki/AES_instruction_set). These instructions are

* `AESENC` and `AESENCLAST` (for the first n-1 round and last round respectively)
* `AESDEC` and `AESDECLAST`
* `AESKEYGENASSIST` (to generate the expanded key)

These instructions can perform AES in 3.5 CPU cycles/byte, while the best software implementation would take 10-30 cycles/byte. [source](http://www.cryptopp.com/benchmarks-p4.html)

The Go Standard Library also has [an implementation](http://golang.org/src/crypto/aes/asm_amd64.s) that uses these instructions.

---

### Closing

I hope you found this post useful. I had a lot of fun learning about AES and implementing it and I wanted to share it with as many people as possible.
