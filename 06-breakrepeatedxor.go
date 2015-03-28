package matasano

// hammingdistance finds the hamming distance between two byte arrays
// hammingdistance(i, j) = hammingweight(i^j)
// Methods to find weight - http://en.wikipedia.org/wiki/Hamming_weight
// Super convoluted and efficient way to find weight - http://stackoverflow.com/a/109025/1109785
func hammingdistance(p, q []byte) int {
	numbitset := func(b byte) int {
		var count int
		for b != 0 {
			b &= b - 1
			count++
		}
		return count
	}

	var distance int
	for i := 0; i < len(p); i++ {
		t := p[i] ^ q[i]
		distance += numbitset(t)
	}
	return distance
}
