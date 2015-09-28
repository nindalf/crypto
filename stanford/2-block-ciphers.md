Block Ciphers
===

A block cipher consists of 2 algorithms E and D. E maps n-bits of plaintext to n-bits of ciphertext using a k-bit key. D does the opposite.

Examples -
1. 3DES. n = 64 bits. k = 168 bits
2. AES. n = 64 bits. k = 128, 192, 256 bits

Procedure:

1. Key expansion - The key is used to generate p round keys.
2. The plaintext is put through p iterations of the Round function `R(k, m)` where k is the round key for that iteration and m is the current state of the message. For 3DES p = 48, for AES-128 p = 10

Note: in practice the block ciphers are significantly slower than stream ciphers. On Prof Boneh's machine, these were the numbers using crypto++ 5.6

Cipher     | Type     | Block/key size | Speed (MBps)
--------   |----------|----------------|--------------|
RC4        | Stream   | n/a            | 126
Salsa 20/12| Stream   | n/a            | 643
Sosemanuk  | Stream   | n/a            | 727
3DES       | Block    | 64/168         | 13
AES        | Block    | 128/128        | 109

---

#### Abstractions

To discuss block ciphers we need 2 abstractions - The **Pseudo Random Function (PRF)** and the **Pseudo Random Permutation (PRP)**

A PRF is defined over (K, X, Y) - F: K x X -> Y such that an "efficient" algorithm to eval F(k, x)

A PRP is defined over (K, X) - E: K x X -> X such that
1. E is one-to-one, and therefore invertible.
2. There exists an efficient algorithm to evaluate E(k, x)
3. There exists an efficient inversion algorithm D (D = E^-1)

Examples

1. 3DES - K x X -> X where K = {0,1}<sup>168</sup> and X = {0,1}<sup>64</sup>
2. AES - K x X -> X where K = X = {0,1}<sup>128</sup>

It is clear that a PRP is a PRF where X = Y and is efficiently invertible. (Not entirely accurate)

PRPs are invertible, whereas PRFs are not. PRPs are block ciphers.

---

#### Secure PRFs

Let F: K x X -> Y be a PRF

Funs[X,Y]: the set of all functions from X to Y. The size of this set is enormous. It would be |Y|<sup>|X|</sup>. For AES, that would be 2<sup>128*2<sup>128</sup></sup> (more than number of atoms in the universe).

A secure function S<sub>F</sub> = {F(k, .) s.t. k ∈ K} ⊆ Funs[X,Y]. F(k, .) = fix the key k and let the second argument float. We are considering the set of all functions for all values of k. For AES, the size of S<sub>F</sub> is 2<sup>128</sup>.

The intuition is that a PRF is secure if a random function in Funs[X,Y] is indistinguishable from a random function in S<sub>F</sub>. Consider an adversary that's trying to distinguish between the pseudo-random function and a truly random function. He will submit a number of messages x ∈ X. We return either F(k, x) (EXP(0)) or f(x) where f <- Funs[X,Y] (EXP(1)). It is secure if he can't distinguish between the two.

In mathematical terms: Adv<sub>PRF</sub>[A,E] = |[Pr(EXP(0)=1) - Pr(EXP(1)=1)]| = negligible. The probability that they guess it was 1 when it was 1 and 1 when it was 0 is almost the same.

Secure PRPs are defined similarly, except instead of a truly random function from Funs[X, Y], the adversary is asked to distinguish between the PRP and a truly random permutation from Perm[X] (ie, a one-to-one fn:X -> X).

Adv<sub>PRP</sub>[A,E] = |[Pr(EXP(0)=1) - Pr(EXP(1)=1)]| = negligible

For all 2<sup>80</sup> algos A, Adv<sub>PRP</sub>[A,AES] < 2<sup>-40</sup>

A secure PRP is a secure PRF if |X| is sufficiently large. Lemma: Let E be a PRP over (K,X). For any q-challenge adversary A: |Adv<sub>PRP</sub>[A,E] - Adv<sub>PRF</sub>[A,E]| < q<sup>2</sup>/2 |X|

---

##### An Application of PRFs

A secure PRF can be used to generate a secure PRG

Let F: K x {0, 1}<sup>n</sup> -> {0, 1}<sup>n</sup> be a secure PRF

then the following G: K x {0, 1}<sup>n</sup> -> {0, 1}<sup>n*t</sup> is a secure PRG

G(k) = F(k, 0) || F(k, 1) || ... || F(k, t)

This is based on the property that PRF F(k, .) is indistinguishable from truly random function f(.). So let G'(k) =  f(0) || f(1) || ... || f(t). G'(k) is indistinguishable from G(k). We know that G'(k) is secure, so G(k) must be too.

Note that G(k) is parallelizable, which is useful.

---

#### The Feistel Network

The Feistel network is the core idea behind DES and many block ciphers (though not AES).

Consider some functions f<sub>1</sub>, ... f<sub>d</sub>: {0,1}<sup>n</sup> -> {0,1}<sup>n</sup>. These functions need not be invertible. But we build an invertible function F :{0,1}<sup>2n</sup> -> {0,1}<sup>2n</sup> based on them.

Each round consists of taking an input R<sub>i-1</sub> and L<sub>i-1</sub>, both n-bits long and computing R<sub>i</sub> and L<sub>i</sub> according to these formulae:

* L<sub>i</sub> = R<sub>i-1</sub>
* R<sub>i</sub> = L<sub>i-1</sub> ⨁ f<sub>i</sub>(R<sub>i-1</sub>) where i = 1, ..., d

To invert, the formulae are

* R<sub>i</sub> = L<sub>i+1</sub>
* L<sub>i</sub> = R<sub>i+1</sub> ⨁ f<sub>i</sub>(L<sub>i+1</sub>) where i = d,..., 1 (applied in reverse order)

Since the calculations performed in forward and inverse is pretty much the same, only one set of hardware is required.

The **Luby-Rackoff theorem** states that if a round function is a secure pseudorandom function (PRF) then 3 rounds of Feistel are sufficient to make the block cipher a pseudorandom permutation (PRP). PRPs are invertible, whereas PRFs are not. In mathematical terms:

f:K x {0,1}<sup>n</sup> -> {0,1}<sup>n</sup> is a secure PRF

=> 3 round Feistel F: K<sup>3</sup> x {0,1}<sup>2n</sup> -> {0,1}<sup>2n</sup> is a secure PRP (K<sup>3</sup> denotes 3 independent keys)

---

#### Data Encryption Standard (DES)

* Uses 16 round Feistel Network.
* The functions used are f<sub>1</sub>, ... f<sub>16</sub>: {0,1}<sup>32</sup> -> {0,1}<sup>32</sup>
* f<sub>i</sub>(x) = F(k<sub>i</sub>, x) where k<sub>i</sub> is a round key derived from the 56-bit key.
* Each round key is 48-bits long
* To invert, use the 16 round keys in reverse order.

The function F(k<sub>i</sub>, x) is shown in the diagram

<center>![The function F of DES](https://upload.wikimedia.org/wikipedia/commons/2/25/Data_Encription_Standard_Flow_Diagram.svg)</center>

1. The half block of 32 bits undergoes expansion to 48 bits in block E
2. The expanded input is XOR-ed with the round key.
3. Then it is broken into 8 blocks of 6-bits each.
4. Each 6-bit block is mapped by the S-box to 4-bits.
5. The 32 bits of output are now permuted, giving the final output

##### S boxes

* S<sub>i</sub>: {0,1}<sup>6</sup> -> {0,1}<sup>4</sup>. In other words each S-box has 2<sup>6</sup> = 64 entries, and each entry is 4-bits long.
* A bad choice would be a linear function of the 6 bits, such as XOR-ing them in various combinations. If it was a linear function, then DES would be a linear function - XOR-ing and permuting. It would be possible to create a 64 x 832 matrix (called B) that when multiplied with the input 832 x 1 matrix (message + 16*48) that would give the 64 x 1 ciphertext.
* Say DES was linear. Then DES(k, m<sub>1</sub>) ⨁ DES(k, m<sub>2</sub>) ⨁ DES(k, m<sub>3</sub>) = B m<sub>1</sub> ⨁ B m<sub>2</sub> ⨁ B m<sub>3</sub> = DES(k, m<sub>1</sub> ⨁ m<sub>2</sub> ⨁ m<sub>3</sub>). It now has a property that can be tested. The challenger can send 3 messages and a fourth which is the XOR of those 3. By testing for this property in the ciphertexts, he can determine if DES was used.
* Worse, Prof Boneh says that you can recover the key in such a linear DES in 832 attempts.
* Even if you chose the S-box at random, it will still be close to linear and you can recover all keys in 2<sup>24</sup> tries.
* So the S-boxes chosen for DES aren't close to linear. That's why they're 6-bits -> 4-bits.

---

#### Exhaustive search attack

Goal: Given a few input-ouput pairs (m<sub>i</sub>, c<sub>i</sub> = E(k, m<sub>i</sub>)), i = 1,..,3 find key k

But first, how do we know that the key is unique? Could there be more than one key that maps m<sub>i</sub> to c<sub>i</sub>?

Lemma:

* Suppose DES is an ideal cipher made of random invertible functions.
* Each key corresponds to a different random function and hence there are 2<sup>56</sup> such functions. 𝝅<sub>1</sub>, ..., 𝝅<sub>2<sup>56</sup></sub>: {0,1}<sup>64</sup> -> {0,1}<sup>64</sup>.
* Then ∀ m, c, there is at most 1 key s.t c=DES(k,m) with probability >= 1- 1/256 (ie, 99.5%)

Proof: Pr[∃ key k' != k: c = DES(k, m) = DES(k', m)] <= 2<sup>56</sup>/2<sup>64</sup> (which is number of possible functions/number of possible mappings). so probability that it doesn't exist is 1 - 1/2<sup>8</sup>. // What is the probability for a 64-bit key?

So how much time will it take to do an exhaustive search of a 56-bit key? A laughably small amount of time - less than a day 15 years ago. "If you encrypt something with DES and you forget the key, don't worry, its easily recoverable." - Prof. Boneh

Workaround:

* Do DES 3 times with keys k<sub>1</sub>, k<sub>2</sub>, k<sub>3</sub>. c = E(k<sub>1</sub>, D(k<sub>2</sub>, E(k<sub>3</sub>, m))).
* Its EDE because a hardware implementation of this can be made single DES by setting all 3 keys equal to each other.
* Exhaustive key-search is no longer possible because the key space is 2<sup>168</sup>.

Problems:

* 3 times slower than DES
* There is an attack that breaks 3DES in approximately 2<sup>118</sup> time though in general > 2<sup>90</sup> is considered a high enough level of security.

##### Why not double DES?

* If c = E(k<sub>1</sub>, E(k<sub>2</sub>, m))
* Then D(k<sub>1</sub>, c) = E(k<sub>2</sub>, m)

This is a "meet-in-the-middle" attack. We need to find the 2 keys k<sub>1</sub> and k<sub>2</sub>. Procedure:

1. Encrypt message under all 2<sup>56</sup> possible keys and sort the ciphertexts. Store this table.
2. Decrypt ciphertext under all 2<sup>56</sup> possible keys and sort the plaintexts. Store this
3. Compare the two tables until a match is found. The corresponding keys are k<sub>1</sub> and k<sub>2</sub>

Time taken = 2<sup>56</sup> x log<sub>2</sub>(2<sup>56</sup>) + 2<sup>56</sup> x log<sub>2</sub>(2<sup>56</sup>) ≈ 2<sup>63</sup>, which is feasible. This is much less than 2<sup>112</sup>, which is what we might have expected. Caveat - it requires 2<sup>56</sup> space.

Therefore, 2DES isn't much more secure than DES, but 3DES is. Note that the attack on 3DES is based on the same principle as this attack. By doing encrypting the message under all 2<sup>112</sup> keys and comparing that to the decryption of ciphertext under 2<sup>56</sup> keys, we can break this in 2<sup>118</sup> time. That's an infeasible amount of time and space.

##### Alternate to protect against Exhaustive Search - DESX

EX((k<sub>1</sub>, k<sub>2</sub>, k<sub>3</sub>), m) = k<sub>1</sub> ⨁ DES(k<sub>2</sub>, (k<sub>3</sub> ⨁ m))

Keysize = 64 + 56 + 64 = 184 bits.

Feasible attack in 2<sup>56+64</sup> = 2<sup>120</sup> is possible. (homework)

Note that k<sub>1</sub> ⨁ DES(k<sub>2</sub>, m) or DES(k<sub>2</sub>, (k<sub>3</sub> ⨁ m)) is worthless.

---

#### Attacks on block ciphers

These attacks can leak the key.

##### Side channel attacks
1. Measure time taken to encrypt/decrypt.
2. Measure current drawn by the smart card.
3. Measure cache-misses by the CPU core running the encryption algorithm while running on another core.

##### Fault attacks

Computing errors in the last round leak the entire key. So the attacker tries to trigger a fault in the CPU. To counter this, correct code should check if its returning the correct result by running the encryption more than once.

##### Linear cryptanalysis

Given many input-output pairs, is it possible to recover the key in less than 2<sup>56</sup> (time taken for exhaustive search)? If their is a linear relation between the input (m) and output (c), you could find certain bits such that

  Pr[m[i<sub>1</sub>] ⨁ ... ⨁ m[i<sub>r</sub>] ⨁ c[j<sub>1</sub>] ⨁ ... ⨁ c[j<sub>v</sub>] = k[l<sub>1</sub>] ⨁ ... ⨁ k[l<sub>u</sub>]] = 1/2 + ϵ for some epsilon

It so happens that DES has a faulty S-box that transmits some linearity from the input to the output. As a result, for DES ϵ = 1/2<sup>21</sup> ≈ 4.77 x 10<sup>-8</sup>

Theorem - given 1/ϵ<sup>2</sup> input-output pairs, you can find that relation in approximately 1/ϵ<sup>2</sup> time.

Applying this to DES given 2<sup>42</sup> input-output pairs, we get 2 bits of the key in 2<sup>42</sup> time. We can get a further 12 bits through the faulty 5th S-box. We brute force the remaining 42 bits, which should take 2<sup>42</sup> time. Time taken for the total attack is 2<sup>42=3</sup> which is much better than 2<sup>56</sup>.

##### Quantum attacks

Generic search problem

Given a function f: X -> {0, 1} that mostly outputs 0. Goal - find x ∈ X s.t. f(x) = 1.

Time taken should be O(|X|), on a classical computer.

On a quantum computer, time taken is O(|X|<sup>1/2</sup>). So a quantum computer could do a quantum exhaustive search, breaking DES in 2<sup>28</sup> time and AES-128 in 2<sup>64</sup> time.


**Lesson from these attacks** - it is extremely difficult to implement these correctly, so the best thing is to use existing libraries. And no matter what, never design a block cipher.

---

#### Advanced Encryption Standard (AES)

* AES is a substitution-permutation network. Unlike a Feistel network where half the bits remain unchanged, this network changes all the bits.
* That also means that each step needed to be designed as reversible. For example, the s-box has an inverse s-box.
* AES allows the implementor to make a trade-off between code size and speed. A lookup-table heavy approach would require more code, but it would also be faster. Its possible to precompute the s-box alone (256bytes x 2), or pre-compute round functions (4kB or 24 kB). The latter replaces SubBytes, ShiftRows and MixColumns by table lookups and the only operation left is XORs with the expanded key.
* Intel and AMD introduced hardware instructions that executes AES faster than software. By using the `AESENC`, `AESENCLAST` and `AESKEYGENASSIST` instructions, its possible to get a 14x speedup over a software implementation. Use as `AESENC XMM1, XMM2` where the first register stores the state and the second the round key and the result is stored in `XMM1`. So for AES-128 (10 rounds) you just need to call `AESENC` 9 times and `AESENCLAST` once, while moving the appropriate round key to `XMM2` after each round.

Attacks
* Key recovery attack in 2<sup>126</sup>, which is slightly better than 2<sup>128</sup>
* Related key attack. Given 4 very similar AES-256 keys and 2<sup>99</sup> input-output pairs, it is possible to recover the keys in ≈2<sup>99</sup> time. In practice, keys are chosen at random and will not be very similar.

[Implementating AES](http://blog.nindalf.com/implementing-aes/)

---

#### Block ciphers from PRGs

Its possible to build PRFs from PRGs. Our goal is to build a block cipher, which is a PRP.

Let G:K -> K<sup>2</sup> be a secure PRG. Let F:K x {0,1} -> K be a 1-bit PRF such that F(k, x∈{0,1}) = G(k)[x] (either the most significant k bits or the least significant).

Theorem: If G is a secure PRG, F is a secure PRF.

In practice, its slow.

---

#### Using PRPs and PRFs

Analyse the security of one-time and many-time keys.

##### One time key

The attacker needs to gain info (semantic security) about the plaintext from one ciphertext

* Electronic Code Book (ECB) mode directly maps the nth block of plaintext to nth block of ciphertext. It is not semantically secure. We should *never* use it for messages more than one block long. Adv<sub>SS</sub>[A, ECB] = 1 (ouput 1 if 2 blocks are equal, 0 if not)
* Deterministic counter (DETCTR) mode. Evaluate the PRF (aka AES or DES) at the point 0, 1, ..., L to generate a pseudo-random pad and ⨁ it with the corresponding message block to get the ciphertext block. This is like a stream cipher and it is semantically secure.

##### Many time key

The attacker has access to multiple ciphertexts. The adversary is allowed to mount a *chosen-plaintext* attack (CPA), meaning he can obtain the encryption of arbitrary messages of his choice.

Goal - to break semantic security. The challenger chooses a key k. The adversary sends q message pairs (m<sub>i,0</sub>, m<sub>i,1</sub>) s.t. |m<sub>i,0</sub>| = |m<sub>i,1</sub>| and i = 1, ..., q. In each case the challenger encrypts one of the two under key k and returns the ciphertext. Semantic security - the adversary is unable to distinguish between always receiving message 0 vs always receiving message 1.

For all efficient adversaries A, the advantage Adv<sub>CPA</sub>[A,E] = |[Pr(EXP(0)=1) - Pr(EXP(1)=1)]|

In this game, if the challenger sets both messages in a pair equal to each other, its a CPA. Say he sends the pair (m<sub>0</sub>, m<sub>0</sub>) and gets back c<sub>0</sub>. Then he sends (m<sub>0</sub>, m<sub>1</sub>) and compares the result with the first result. If he got c<sub>0</sub>, he would know that m<sub>0</sub> was encrypted. In this case, Advantage would be 1. Hence we can conclude that any block cipher that encrypts a message to the same ciphertext deterministically is *not* semantically secure.

Solutions to the Chosen Plaintext Attack (CPA)

* Randomized encryption.
  * Encrypting the plaintext gives different ciphertexts every time.
  * The ciphertext is longer than the plaintext => len(ciphertext) = len(plaintext) + len(random-bits).
  * E(k, m) = [r <- R, output (r, F(k, r) ⨁ m)].
  * F(k, r) is indistinguishable from a truly random function f(r). If r never repeats, output of f(r) is random, uniform, independent every time.
  * f(r) ⨁ m is therefore also random, uniform and independent
  * (r, F(k, r) ⨁ m) is therefore also random, uniform and independent

* Nonce-based encryption
  * E(k, m, n) where n is chosen such that (k, n) is unique. The pair is *never* used more than once.  
  * It can be public, it doesn't need to be random or uniform
  * A simple counter is a good nonce. It requires the encryptor to store state between messages. If the decryptor stores state as well (and will receive messages in the same order), the nonce doesn't have to be included in the packet. Thus, it achieves CPA-security and doesn't increase ciphertext length.
  * A random nonce is also good. This is the same as randomized encryption. In this case, the sender does not need to maintain state between encryptions. If you have multiple devices using the same key, this is better than using a counter, to be certain that (k, n) is not repeated.
  * We must assume that the adversary is capable of choosing the nonce. This is part of CPA-security. However, he must choose distinct nonces because real world systems are not going to reuse nonces.

---

#### Cipher Block Chaining (CBC) mode

<center>![CBC Encryption](https://upload.wikimedia.org/wikipedia/commons/8/80/CBC_encryption.svg)</center>

<center>![CBC Decryption](https://upload.wikimedia.org/wikipedia/commons/2/2a/CBC_decryption.svg)</center>

Implementation of AES-CBC - in [Go](https://github.com/nindalf/crypto/blob/master/matasano/10-aes_cbc.go)

**CBC theorem**

* For any message of length L > 0. If E is a secure PRP over (K, X), then E<sub>CBC</sub> is semantically secure under CPA over (K, X<sup>L</sup>, X<sup>L+1</sup>) (input of length L, output of length L+1).
* For any q-query adversary A, attacking E<sub>CBC</sub>, there exists a PRP adversary B s.t. Adv<sub>CPA</sub>[A, E<sub>CBC</sub>] <= 2 x Adv<sub>PRP</sub>[B, E] + 2q<sup>2</sup>L<sup>2</sup>/|X|.
* CBC is only semantically secure if both terms on the right are negligible. The first already is.
* Therefore the error term 2q<sup>2</sup>L<sup>2</sup> << |X|. q is the number of times we've used the key k. L is the length of the max message. For AES the block size is 128, so |X| is 2<sup>128</sup>.
* If we want the error term to be negligible, say 1/2<sup>32</sup>, then qL should be 2<sup>48</sup> or less.
* So after encrypting 2<sup>48</sup> AES blocks we should change the key.
* The corresponding value for 3DES is 2<sup>16</sup> since DES uses 64-bit blocks. The key needs to be changed after encrypting 512kB with 3DES

Attack on CBC

* If an attacker can predict the IV, Advantage becomes 1
* First he sends 2 messages 0, such that he gets IV1.
* He predicts IV, so he sends one message m<sub>0</sub> = IV ⨁ IV1 and the other message m<sub>1</sub> is just != m<sub>0</sub>.
* If he receives IV1, then he knows its m<sub>0</sub>. Else its m<sub>1</sub>.
* TLS used/uses non-random IVs

Nonce-based CBC

* A non-random nonce can be used to generate the IV. If Bob knows the nonce, it doesn't need to be sent with the ciphertext.
* The nonce is encrypted with key k1 and then fed in as the IV.
* It *must not* use the the same key k used for the ciphertext.

---

#### Counter (CTR) mode

<center>![CTR Diagram](https://upload.wikimedia.org/wikipedia/commons/4/4d/CTR_encryption_2.svg)</center>

<center>![CTR Diagram](https://upload.wikimedia.org/wikipedia/commons/3/3c/CTR_decryption_2.svg)</center>

Implementation of AES-CTR in [Go](https://github.com/nindalf/crypto/blob/master/matasano/10.5-aes_ctr.go)

Procedure to encrypt a message of length L blocks:

* Let F be a secure PRF. F: {0,1}<sup>128</sup> -> {0,1}<sup>128</sup>. We don't need the decrypting (ie, inverting) functionality, so we use a PRF.
* IV is chosen at random for every message.
* F(k, IV + i) is calculated for i = 0, ..., L-1
* c[i] = m[i] ⨁ F(k, IV + i)
* The IV is prepended to the ciphertext

This is superior to CBC. It is also parallelizable, unlike CBC.

**CTR theorem**

* For any q-query adversary A, attacking E<sub>CBC</sub>, there exists a PRF adversary B s.t. Adv<sub>CPA</sub>[A, E<sub>CTR</sub>] <= 2 x Adv<sub>PRF</sub>[B, F] + 2q<sup>2</sup>L/|X|.
* If we want the error term to be negligible, say 1/2<sup>32</sup>, then qL<sup>1/2</sup> should be 2<sup>48</sup> or less.
* That means 2<sup>32</sup> ciphertexts, each of length 2<sup>32</sup>.
* So after encrypting 2<sup>64</sup> AES blocks we should change the key.

---

#### Comparison of CBC and CTR

Criteria                 | CBC                   | CTR   | Notes
-------------------------|-----------------------|-------|
uses                     | PRP                   | PRF   | CTR is more general
parallel processing      | no                    | yes   |
security of rand. enc.   | 2q<sup>2</sup>L<sup>2</sup> << sizeof(X)|  2q<sup>2</sup>L << sizeof(X) | Number of blocks before key needs to be changed: CBC - 2<sup>48</sup> CTR - 2<sup>64</sup>
dummy padding block      | yes                   | no    | the block of 16 bytes of 16
1 byte msgs (nonce-based)| 16x expansion         | no expansion |

---

Note on integrity: None of the methods discussed here ensure message integrity.

* Stream ciphers
* Deterministic counter mode
* Random CBC
* Random CTR
