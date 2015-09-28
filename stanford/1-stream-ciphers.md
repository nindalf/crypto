Stream Ciphers
===

#### Cipher

* It is defined over the triple of sets (𝒦, ℳ, 𝓒) ie, the sets of all possible keys (keyspace), all possible messages and all possible ciphertexts. The triple defines the environment over which the cipher is defined.
* A cipher is made up of two "efficient" algorithms - the encryption algo E and the decryption algo D.
* E: 𝒦 x ℳ -> 𝓒
* D: 𝒦 x 𝓒 -> ℳ
* Correctness property. ∀ m ∈ ℳ, ∀ k ∈ 𝒦: D(k, E(k, m)) = m
* Efficient means different things to different people. For some people it means algorithmic complexity. For others, it means how many ms taken to encrypt 1GB of data.
* E is sometimes randomized. D is deterministic

---

#### One time pad

* Key is a long sequence of bits, as long as the message that needs to be encrypted
* c = E(k, m) = k ⨁ m
* m = D(k, c) = k ⨁ c = k ⨁ (k ⨁ m) = (k ⨁ k) ⨁ m = 0 ⨁ m = m (Reversible!)
* From the discussion on discrete probability, k ⨁ m is uniformly distributed since k is uniformly distributed. Thus the distribution of k ⨁ m0 is indistinguishable from the distribution of k ⨁ m1.
* Very fast, but the keys are too long. If you could transfer a key that long securely, you can use the same to transfer the message itself. So its hard to use in practice.
* Its a good cipher.

---

#### A good cipher

* According to Shannon, a good cipher generates a ciphertext that reveals no "information" about the plaintext.
* A cipher (E, D) over (𝒦, ℳ, 𝓒) has perfect secrecy if ∀ m<sub>0</sub>, m<sub>1</sub> ∈ ℳ (|m<sub>0</sub>| = |m<sub>1</sub>|) and ∀ c ∈ 𝓒: Pr[E(m<sub>0</sub>, k) = c] = Pr[E(m<sub></sub>, k) = c] where k is uniform in 𝒦.
* In other words, on observing a ciphertext c, it is equally likely that it could have come from any m ∈ ℳ, ie, all m<sub>i</sub> messages are equally likely. Thus intercepting c tells you nothing about the message and no ciphertext-only attacks are possible on such a cipher.
* But Shannon also proved this - for a cipher to be perfect, |𝒦| >= |ℳ|, so that pretty much excludes everything apart from the one time pad. Another way of stating it is that the key-len  >=  message-len
* Therefore we need a less stringent definition of a good cipher. (covered later in this lesson)

---

#### Pseudorandom Generator

It is a function that takes an s-bit string (seed), and maps it onto a much larger output string. Ie, G: {0,1}<sup>s</sup> -> {0,1}<sup>n</sup> where n >> s. Some properties

1. efficient to compute.
2. It should be deterministic, the only random part is the seed.
3. The output should "look" random.
4. It should be unpredictable. G:{0,1}<sup>s</sup> -> {0,1}<sup>n</sup> is predictable if ∃ an efficient algorithm A and ∃ 1 <= i <= n s.t. Pr[A(G(k))|<sub>first i bits</sub> = G(k)|<sub>i+1</sub>] = 1/2 + ϵ for some non-negative ϵ. In other words, G is predictable if given the first i bits of output, there exists no efficient algorithm that can predict that i+1th bit with probability greater than 1/2 + ϵ where ϵ is non-negative.

The challenge is in satisfying all of these criteria. Since G is deterministic, it is a one-to-one function. Since s << n, only a small subset of n-length strings are possible outputs. Nevertheless, the n-length string should be as uniformly distributed as possible.

Note : ϵ is a scalar. For practitioners, (ϵ >= 1/2<sup>30</sup>) is non-neglible, meaning if you used a key for encrypting a GB of data, then an event that happens with this probability will probably happen after a gigabyte of data. Since a GB is not that high, this event is likely to happen. An event that is (ϵ <= 1/2<sup>80</sup>) is negligible, one that is unlikely to happen over the lifetime of the key

Examples of bad PRGs
* Linear congruential generator - r[i] = (r[i-1] * a + b) mod p  - very easy to predict.
* glibc random() - actually used by Kerberos v4

---

#### Stream cipher

* An attempt to make OTP practical. Instead of using a random key, we use a pseudo-random key. The key will be used as a seed.
* Stream ciphers cannot have perfect secrecy because the key length is less than the message length and security would depend on the PRG

Problems with OTP used as a stream cipher.
1. If the pad is reused, it is insecure. It basically becomes repeating-key XOR, which is breakable thanks to the sufficient redundancy in English and ASCII encoding. Russians used 2-time pads from 1941-46, Microsoft Point-to-Point protocol used it, Wi-Fi protocol WEP uses it (after every 16M frames). In WEP the key used to encrypt frames 1, 2, .. was (1||k), (2||k). Since its a 24-bit counter, it cycles. Also, k doesn't change long term, and the PRG used (RC4) depends on the lower bits changing. To prevent this:
  * If OTP is being used between client and server, 2 separate keys should be used.
  * For network traffic, negotiate a new key for every session.
  * For disk encryption, do not use a stream cipher.
2. No integrity. The ciphertext is malleable. Modifications to the ciphertext are undetected and have a predictable impact on the ciphertext. For example, the ciphertext of "attack at dawn" - "09e1c5f70a65ac519458e7e53f36" can be trivially changed to "09e1c5f70a65ac519458e7f13b33", meaning "attack at dusk".

---

#### Examples of Stream ciphers

* RC4 (1987). Takes a 128-bit key, expands this to 2048 bits and executes a simple loop with the state. Each loop gives 1 byte. Its used in HTTPS and WEP. Not recommended for use today. Problems
  1. Bias in initial output - For example Pr[output[1] == 0] = 2/256 (it should be 1/256). Its recommended that the first 256 bytes of output of RC4 be ignored.
  2. The probability of getting output [0,0] should be 1/256<sup>2</sup>. After a few GB of output, it becomes 1/256<sup>2</sup> + 1/256<sup>3</sup>. It can be used to distinguish the output of the generator from truly random bytes.
  3. Related key attacks like in WEP. If the keys are closely related, it is possible to recover the key
* Linear Feedback Shift Registers. Take a seed. Every loop, shift the state right. The msb is the xored output of a few selected bytes or all bytes. Easy to implement in hardware. It is very broken. Examples, all of which are broken, but difficult to change since they're implemented in hardware.
  1. Content Scrambling System ie CSS (used in DVD) uses 2 LFSRs. The seed used was 40 bits long (due to USG export regulations). It seeded a 17-bit LFSR and a 25-bit LFSR (leading 1s added). The output of both go through addition-modulo-256. With DVDs, the first 20-odd bytes of plaintext were known. We iterate through the possible outputs of the 17-bit one, subtract it from the known bytes and check if the remainder could possibly have been generated by a 25-bit LFSR
  2. GSM (A5/1,2) uses 3 LFSRs
  3. Bluetooth uses 4 LFSRs
* eStream. PRG used is {0,1}<sup>s</sup> x R = {0,1}<sup>n</sup>. R is a nonce, a value which isn't repeated over the lifetime of the key. E(m, k, r) = m ⨁ PRG(k, r). The pair (k, r) is not used more than once. Since the pair isn't used twice, the key can be reused.
  * The PRG used in eStream is Salsa20: {0,1}<sup>128 or 256</sup> x {0,1}<sup>64</sup> -> {0,1}<sup>n</sup> where max n = 2<sup>73</sup> bits.
  * Salsa20(k, r) := H(k, (r, 0)) || H(k, (r, 1)) || ...
  * Its fast on both hardware and software, because the small h function can be implemented using x86 SSE2 instructions. Its about 5 times faster than RC4

---

#### PRG Continued

G: K -> {0,1}<sup>n</sup> be a PRG. The goal is that the output should be indistinguishable from a truly uniform distribution. This is difficult because the set of {0,1}<sup>n</sup> is very large while the seed space is quite small. Therefore, only a subset of {0,1}<sup>n</sup> is possible. Despite that, an adversary who looks at the output of the generator would find it impossible to distinguish from the output of the uniform distribution

##### Statistical tests

A statistical test on {0,1}<sup>n</sup> is an algorithm A(x) tells if a PRG is random (1) or not random (0)

1. Iff |num(zeros) - num(ones)| <= 10 * sqrt(n)
2. Iff |num(two consecutive zeros)| - n/4 <= 10 * sqrt(n) // 00, 01, 10, 11 are all equally likely so they should be close to n/4
3. Iff max-num-consecutive(0) <= 10* log2(n)

Statistical tests in general are not that great an idea. But how do we compare statistical tests? We look at advantage

Adv[A, G] := | Pr[A(G(k)) == 1] - Pr[A(r) == 1] | where k is taken from the keyspace and r is truly random. Obviously Adv ∈ [0,1]. If Adv is close to 1, then the statistical test behaved completely differently in the two cases - it was able to distinguish between pseudo-random and truly random. In other words, statistical test A breaks generator G with advantage Adv[A, G]

Therefore, we have a new definition of secure PRGs - if no efficient statistical test can distinguish between the generator and truly random output. In other words, ∀ "efficient" A: Adv[A, G] is negligible. Not just a particular battery of statistical tests, the definition mentions ∀ efficient tests.

There are no known provably secure PRGs. P != NP kappa.

Facts about secure PRGs

1. A secure PRG is unpredictable. We prove the contrapositive, if PRG is predictable, it is insecure. Suppose A is an efficient algorithm such that Pr[A(G(k)|1...i) = G(k)|i=1] = 1/2 + ϵ. ϵ is non-negligible, say 1/1000. Then to test A, we define B(X). We ask A to predict after each input, and output 1 if it was correct and 0 if it wasn't. Then we ask Pr[B(x) = 1]. Its clear that Pr[B(r) == 1] = 1/2. Pr[G(k) = 1] > 1/2 + ϵ. => Adv[B, G] = ϵ

Yao's theorem: an unpredictable PRG is secure. If no next-byte predictor can predict the i+1th bit after seeing the first i input, then no statistical test can.

Let P<sub>1</sub> and P<sub>2</sub> be 2 distributions over {0,1}<sup>n</sup>. They are computationally indistinguishable if ∀ A: |Pr[A(P<sub>1</sub>) ==1] - Pr[A(P<sub>2</sub>) == 1]|

---

#### Semantic security

To prove: If you use a secure PRG, you will get a secure stream.

Recapping from earlier, according to Shannon a secure cipher shouldn't reveal any "information" about the plaintext. However, we need a less stringent definition because only a OTP satisfies Shannon's definition.

Shannon said - Pr[E(k, m<sub>0</sub>) == c] == Pr[E(k, m<sub>1</sub>) == c]

A weaker definition is Pr[E(k, m<sub>0</sub>) == c] ≈<sub>p</sub> Pr[E(k, m<sub>1</sub>) == c]

Another way of looking at semantic security.
* The adversary gives the challenger (kind of like an oracle) 2 messages m<sub>0</sub>, m<sub>1</sub> ∈ M, |m<sub>0</sub>|=|m<sub>1</sub>|.
* The challenger will encrypt one of them and return it - E(k, m<sub>b</sub>). The adversary has to guess which message it received.
* The advantage of the adversary wrt semantic security is Adv<sub>SS</sub> = |Pr[W<sub>0</sub>] - Pr[W<sub>1</sub>]| ∈ [0,1]. Pr[W<sub>b</sub>] is the probability that the adversary guessed "b".
* Interpretation of Advantage. If its 0, the adversary wasn't able to guess which message it was. If its 1, he was able to distinguish an encryption of m<sub>0</sub> from an encryption of m<sub>1</sub> ie, its completely broken.

Thus the definition - E is secure if ∀ "efficient" adversaries A Adv<sub>SS</sub>[A, E] is negligible.

Example. Suppose the adversary can always tell the LSB of m<sub>b</sub>. It sends m<sub>0</sub> and m<sub>1</sub> such that lsb(m<sub>0</sub>) = 0 and lsb(m<sub>1</sub>) = 1. Thus the advantage would be |Pr[Exp(0) = 1] - Pr[Exp(1) = 1]| = |0 - 1| = 1. (Probability that the challenger guessed 1 for m<sub>0</sub> - Probability that the challenger guessed 1 for m<sub>1</sub>).  

This holds for any information about the plaintext, not just the lsb. It could be msb, bit 7, the xor of all bits etc

// What I'm not clear about - the difference between the Adv fn for PRGs and ciphers.
