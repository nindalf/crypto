Message Integrity
====

Goal is integrity, not confidentiality. Alice wants to send a message m and wants to prevent any tampering with the message. The solution is

#### Message Authentication Code (MAC).

* Alice and Bob have a shared key k.
* She uses a signing algorithm S to generate a short tag (say 100 bytes). tag <- S(k, m) and appends it to the message.
* Bob receives both. He runs a verification algorithm V(k, m, tag) that outputs "yes" or "no", depending on whether the tag corresponds to the message and key. This indicates if the message has been tampered with.

The algos (S, V) are defined over (𝒦, ℳ, 𝓣) (key space, message space, tag space) s.t.

* S(k, m) outputs t in 𝓣
* V(k, m, t) outputs "yes" or "no"
* S and V are consistent. ∀ m ∈ ℳ, ∀ k ∈ 𝒦: V(k, m, S(k, m)) = "yes"

It is *not* possible to do this without a shared key. If you sent the message with a CRC, it is always possible to intercept the message, tamper with it and append the new CRC. The CRC is designed to detect random errors, not malicious errors. The key ensures that there is something that Alice can do which can't be replicated by the attacker.

Real world use case - An OS would generate tags for all its files using the user's password as k. If a virus modifies any files, they would no longer match the tags. The virus can't generate new tags either.

---

#### Secure MACs

Our goal:

* Given (m, t), the attacker cannot generate a (m, t') for t' != t.

An attacker has these attributes:

* Attacker's power - the chosen message attack. The attacker with choose q messages m<sub>1</sub>, ..., m<sub>q</sub>. Alice will compute the corresponding tags t<sub>i</sub> <- S(k, m<sub>i</sub>).
* Attacker's goal - existential forgery. Produce a valid message pair such that (m, t) ∉ {(m<sub>1</sub>, t<sub>1</sub>), ..., (m<sub>q</sub>, t<sub>q</sub>)}

The game:
* After the attacker submits q messages to the challenger and receives q tags, he submits a pair (m, 1)
* Challenger outputs b = 1 if V(k, m, t) = "yes" and (m, t) ∉ {(m<sub>1</sub>, t<sub>1</sub>), ..., (m<sub>q</sub>, t<sub>q</sub>)}
* b = 0 otherwise
* I = (S, V) is a secure MAC if for all "efficient" attackers, Adv<sub>MAC</sub>[A, I] = Pr[Challenger outputs 1] is negligible.
* In practice, this places a constraint on the length of the tag. If the length of the tag is 5, then the Advantage is 1/32, which is non-negligible. It should be at least 64, 96, 128 bits long

---

#### A secure PRF

For a PRF F: K x X -> Y, define a MAC I<sub>F</sub> = (S, V) s.t.:

* S(k, m) = F(k, m)
* V(k, m, t): output "yes" if t = F(k, m) and "no" otherwise

Theorem: If F is a secure PRF and f |Y| is sufficiently large(say 2<sup>80</sup>), I<sub>F</sub> is a secure MAC. In particular for every adversary A attacking the MAC, there exists an adversary B attacking the PRF such that

Adv<sub>MAC</sub>[A, I<sub>F</sub>] <= Adv<sub>PRF</sub>[B, F] + 1/|Y|.

Adv<sub>PRF</sub>[B, F] is negligible since F is a secure PRF. So for I<sub>F</sub> to be a secure MAC, 1/|Y| should be negligible as well.

To prove that Adv<sub>PRF</sub>[B, F] is negligible, we replace it by a truly random function f(x). The adversary needs to predict the tag of a message m based on the q pairs provided to him by the challenger. However, the output of a truly random function at the point m is not dependent on its value at any other point, so the adversary would be guessing points in Y. Pr[guessing this correctly] = 1/|Y|. Since F is a PRF, the adversary will behave the same whether we give him F or f.

Truncating the output of the PRF works too. Lemma: Suppose F: K x X -> Y is a secure PRF. Then F<sub>t</sub>(k, m) = F(k, m)[0:t] for all 1 <= t <= n. A MAC based on this PRF would be secure as long as t > 2<sup>64</sup>.

---

#### Examples

* AES is a MAC for 16-byte messages

For larger inputs, other functions (Big-MACs, according to Prof. Boneh) are used

1. CBC-MAC (Used in banking), CMAC. Both of these commonly use AES
2. NMAC (basis of HMAC)
3. PMAC
4. HMAC (Used in SSL, IPSec, SSH)

The first 3 constructed a MAC for large messages by constructing a PRF for large messages.

---

#### Encrypted CBC-MAC (ECBC)

Let F be a PRP F: K x X -> X. We define a new PRF F<sub>ECBC</sub>: K<sup>2</sup> x X<sup><=L</sup> -> L

<center>![ECBC working](https://upload.wikimedia.org/wikipedia/en/a/ae/CBC-MAC_%28encrypt_last_block%29_structure.svg)</center>

The first stage, where the encryptions are done with the key k<sub>1</sub> is called the Raw-CBC function. This alone is not secure, which is why we need to encrypt it with the second key. The output can be truncated to t bits, as long as t > 2<sup>64</sup>.

---

#### Nested MAC (NMAC)

Let F be a PRF F: K x X -> X. We define a new PRF F<sub>NMAC</sub>: K<sup>2</sup> x X<sup><=L</sup> -> K

* The message is broken into blocks equal to the blocksize of the PRF.
* The output of each stage is used as the key for the following stage and the input is the next message block.
* The final output t lies in K.
* This function is called the cascade function. It is not a secure MAC.
* Typically this method is used with PRFs where size of x is much larger than size of k. So we take the output of the cascade t, append a fixed pad (fpad) to it. (t || fpad) ∈ X
* tag = F(k<sub>1</sub>, (t || fpad)) ∈ K

The problem with NMAC is that key expansion needs to be done at every step.

---

#### Security of ECBC and NMAC

##### Analysis of security of the first function

* **Cascade function** can be forged with one chosen message query.
  1. We have the output t for a message, and we have access to function F.
  2. We calculate F(t, w) so now we have MAC of message (m || w).
  3. There is no step 3. This is an extension attack.
* **Raw-CBC function** can also be forged with one chosen message
  1. Choose an arbitrary one block message m ∈ M
  2. Get the tag t corresponding to m
  3. Construct a two message block (m || (t⨁m)). The tag corresponding to this is F(k, (m || (t⨁m))) = F(k, F(k, m) ⨁ (t⨁m)) = F(k, t⨁(t⨁m)) = F(k, m) = t
  4. This is not secure

##### Analysis of security of the entire function

For all efficient, q-query adversaries A attacking F<sub>ECBC</sub> or F<sub>NMAC</sub>, there exists an efficient adversary B s.t

* Adv<sub>PRP</sub>[A, I<sub>ECBC</sub>] <= Adv<sub>PRP</sub>[B, F] + 2q<sup>2</sup>/|X|
* Adv<sub>PRF</sub>[A, I<sub>NMAC</sub>] <= Adv<sub>PRF</sub>[B, F] + 2q<sup>2</sup>/|K|
* ECBC is secure as long as q << |X|<sup>1/2</sup>.
* NMAC is secure as long as q << |K|<sup>1/2</sup>.
* If AES is used with ECBC and we want the advantage to be less then 2<sup>-32</sup>, the key should change every 2<sup>48</sup> messages. The corresponding value for DES is 2<sup>16</sup> messages.
* According to the birthday paradox after |X|<sup>1/2</sup> many messages we are bound to encounter a collision such that F(k, x) = F(k, y).
* Then we can compute F(k, y || w) by requesting the tag F(k, x || w). This is the extension property.

---

#### MAC padding

Problem - if we apply padding (say, appending zeros) to a message m0, we say that MAC(m0) = MAC(m0||000). This allows an attacker to mount an existential forgery attack. He would know the tags corresponding to m||0, m||00 etc.

Solution - The padding must therefore be a one-to-one function.

ISO - Add 100..000 to the block till its a multiple of block size. If len(m) % blocksize == 0, then append a dummy block of 100..0000. Not adding the dummy block makes it insecure. Then MAC(m[0:13]) is the same as MAC(m[0:13] || 100)

---

#### CMAC

<center>![CMAC](http://i.imgur.com/dZpI4pi.png)</center>

* Take the key k, derive two keys k<sub>1</sub> and k<sub>2</sub> from it.
* If the last block of the message requires padding, pad it, XOR it with k<sub>1</sub> and then apply F(k, m<sub>i</sub>)
* If it doesn't require padding, XOR it with k<sub>2</sub> and then apply F(k, m<sub>i</sub>)
* No final encryption is needed.
* No extension attack is possible

---

#### Parallel MAC (PMAC)

Let F: K x X -> X be a PRF. Define a new PRF F<sub>PMAC</sub>: K<sup>2</sup> x X<sup><=L</sup> -> X

Each message block m[i] is XOR-ed with P(k, i). The result is fed into F(k<sub>1</sub>, .) and finally everything is XOR-ed together and fed into F(k<sub>1</sub>, .) Formula:

temp = F(k<sub>1</sub>, P(k, 1)⨁m[1]) ⨁ F(k<sub>1</sub>, P(k, 2)⨁m[2]) ⨁ ... ⨁F(k<sub>1</sub>, P(k, L)⨁m[L])
tag = F(k<sub>1</sub>, temp)

##### Properties:

* If the each block wasn't XOR-ed with P(k, i) order would no longer matter and it would be possible to compute the existential forgery of any message simply by reordering blocks.
* P(k, i) is very simple to compute.
* Padding is the same as CMAC.
* If F is a PRP instead of a PRF, then PMAC is incremental. If one block changes m[i], we can quickly recompute the PMAC for the message with one changed block m'[i]

##### Security

For all efficient, q-query adversaries A attacking F<sub>PMAC</sub> there exists an efficient adversary B s.t

* Adv<sub>PRF</sub>[A, F<sub>PMAC</sub>] <= Adv<sub>PRF</sub>[B, F] + 2q<sup>2</sup>L<sup>2</sup>/|K|
* PMAC is secure as long as qL << |X|<sup>1/2</sup>.

---

#### One time MAC

A key is used only to compute the MAC of a single message. An adversary only ever has access to a single message-tag pair (m, t). Based on this key needs to compute a valid pair (m', t')

##### Procedure

Let q be a large prime number, slightly larger than our block size. For example q = 2<sup>128</sup>+51

key = (k, a) ∈ {1, q}<sup>2</sup> (2 random integers in [1,q])

* Break the message into blocks where each block is say L = 128-bits.
* Each block is considered an integer in the range [0, 2<sup>128</sup>-1].
* Construct the polynomial of degree L P<sub>msg</sub>(x) = m[L].x<sup>L</sup> + ... + m[1].x (no constant term)
* We evaluate the polynomial at k and then add a
* Final result is modulo q

##### Properties
* Knowing the value of the MAC at one message, it tells you nothing about the value of the MAC for any other message.
* Such a scheme can be secure against all adversaries, not just efficient ones
* It can be much faster to compute than PRF-based MACs.
* Completely insecure if used more than once.

---

#### Many time MACs (Carter-Wegman)

Let (S, V) be a secure one-time MAC over {K, M, {0,1}<sup>n</sup>}

Let F: K<sub>F</sub> x {0,1}<sup>n</sup> -> {0,1}<sup>n</sup> be a secure PRF.

Then the Carter-Wegman MAC is CW((k<sub>1</sub>, k<sub>2</sub>), m) = (r, F(k<sub>1</sub>, r) ⨁ S(k<sub>2</sub>, m))

Properties

* S is fast to compute, even if m is of the order of GB.
* F is slow, but the randomly chosen nonce r is small ({0,1}<sup>n</sup>).
* Verification is V(k<sub>2</sub>, m, F(k<sub>1</sub>, r) ⨁ tag)
* It is *not* a PRF unlike the previous MACs under discussion, since there could be many valid tags for the same input.

---

#### Collision Resistance

Let H: M -> T be a hash function. (|H| >> |T|)

A collision for the function H is a pair m<sub>0</sub>, m<sub>1</sub> ∈ M such that H(m<sub>0</sub>) = H(m<sub>1</sub>) when m<sub>0</sub> != m<sub>1</sub>. Such a collision seems likely because |H| >> |T| and by pigeonhole principle, arbitrarily many messages must map to the same tag.

A function H is collision resistant if it is hard to find collisions for this function. In formal terms, a function H is collision resistant if for all "explicit", "efficient" algos A: Adv<sub>CR</sub>[A, H] = Pr[A outputs collision for H] is negligible  

Meaning of "explicit" - its not enough to show that a pair of messages that collide, since we know that is certain to happen. An explicit algo A is actual code that will generate such messages that trigger collisions.

A collision resistant hash can be used to protect file integrity. Say you're distributing n files. Put the Hash of each into a read-only space. An attacker could modify the files, but not in a way that its hash does not change, and he can't modify the read-only space (by definition). This is cool, because a key isn't required.

##### MACs from collision resistance

Let I = (S, V) be a MAC for short messages over (K, M, T). eg. AES.

Let H: M<sup>big</sup> -> M be a collision resistant hash function

Define I<sup>big</sup> over (K, M<sup>big</sup>, T) such that

* S<sup>big</sup>(k, m) = S(k, H(m))
* V<sup>big</sup>(k, m, t) = V(k, H(m), t)

Concept applied here - we use the property of collision resistance to use a primitive (small MAC) to create a large MAC. Example - S(k, m) = AES<sub>2-block-CBC</sub>(k, SHA-256(m)). If H wasn't collision resistant, then it would be trivial to find 2 messages such that H(m<sub>0</sub>) = H(m<sub>1</sub>), then find t = I<sup>big</sup>(m<sub>0</sub>) and output the same tag for m<sub>1</sub>. (1-chosen-plaintext)

Theorem - If I is a secure MAC and H is collision resistant, then I<sup>big</sup> is a secure MAC.

---

#### Generic Birthday Attack

Exhaustive search attacks on Block Ciphers forces the key size to be larger. Similarly, the birthday paradox tells us that to find a collision in a output space of 2<sup>n</sup>, we only need to try 2<sup>n/2</sup> inputs.

Let H: M -> {0,1}<sup>n</sup> be a hash function (|M| >> 2<sup>n</sup>). The generic algo to find a collision is

1. Choose 2<sup>n/2</sup> messages in M
2. Compute the hash for each
3. Check if any hash is equal. If no, go to step 1

The number of iterations of this algorithm is small.

##### The Birthday Paradox

Let r<sub>1</sub>, ..., r<sub>n</sub> ∈ {1, ..., B} be independent, identically distributed integers.

Theorem: When n = 1.2 x B<sup>1/2</sup> then Pr[∃ i != j, r<sub>i</sub> = r<sub>j</sub>] >= 1/2

Proof:

* Consider a uniform distribution (ie, the worst case) r<sub>1</sub>, ..., r<sub>n</sub>
* Pr[∃ i != j, r<sub>i</sub> = r<sub>j</sub>] = 1 - Pr[∀ i != j, r<sub>i</sub> != r<sub>j</sub>]
* Probability that r<sub>2</sub> doesn't collide with r<sub>1</sub> = (B-1)/B, since r<sub>1</sub> took one slot
* Similarly, the probability that r<sub>i+1</sub> doesn't collide with r<sub>1</sub>, ... , r<sub>i</sub> is (B-i)/B, since the first i numbers took i slots.
* So 1 - Pr[∀ i != j, r<sub>i</sub> != r<sub>j</sub>] = 1 - (B-1)/B x (B-2)/B x ... x (B-n+1)/B
* It is possible to multiply in this manner because the numbers are independently distributed.
* Restating the prev line, 1 - (B-1)/B x (B-2)/B x ... x (B-n+1)/B = 1 - ∏ (1 - i/B)
* But 1 - x <= e<sup>-x</sup>
* So Pr[∃ i != j, r<sub>i</sub> = r<sub>j</sub>] >= 1 - ∏ e<sup>-i/B</sup>
* The latter term is 1 - e<sup>(-1/B)∑i</sup>
* The sigma term is n(n+1)/2, which is >= n<sup>2</sup>/2
* So Pr[∃ i != j, r<sub>i</sub> = r<sub>j</sub>] >= 1 - e<sup>-n<sup>2</sup>/2B</sup>
* Substituting n = 1.2 x B<sup>1/2</sup> (from the theorem statement), we get 1 - e<sup>-n<sup>2</sup>/2B</sup> = 1 - e<sup>-0.72</sup> = 0.53 > 1/2
* Therefore Pr[∃ i != j, r<sub>i</sub> = r<sub>j</sub>] > 1/2. Hence proved

This proof only holds for uniform distributions, but it is possible to argue that the bound for a non-uniform distribution will be lower.

Intuition behind this: the probability of a collision of birthdays with n = 23 people is 1.2, which seems high. However, we need to consider that for n people, we need to consider the number of pairs of people. Each pair collides with probability 1/B and if there are B pairs, then the probability is high.

This distribution reaches probability

* 1 at n = B (pigeonhole principle)
* 0.99 at n = 3 sqrt(B)
* 0.9 at n = 2 sqrt(B)
* 0.5 at n = 1.2 sqrt(B)
* 0.42 at n = sqrt(B)
* Drops to 0 very quickly below n = sqrt(B)

On this basis the generic attack succeeds in O(2<sup>n/2</sup>) time and O(2<sup>n/2</sup>) space

For this reason, a collision resistant hash function that outputs 128-bits isn't considered secure. Although SHA-1 (output 160 bits) hasn't been broken yet, it is considered only a matter of time before it is.

---

#### Merkle-Damgard iterated construction

<center>![Merkle-Darmgard procedure](https://upload.wikimedia.org/wikipedia/commons/e/ed/Merkle-Damgard_hash_big.svg)</center>

* Let h: T x X -> T be a collision resistant hash function for small size inputs (aka compression function).
* We break the message into blocks and feed it into h iteratively.
* The IV is fixed permanently for an algorithm .
* The padding to the final block is 1000... || message-len(64-bits). If there is no space in the last block, we add a dummy block.
* we thus obtain H: X<sup><=L</sup> -> T

Theorem: if h is collision resistant, so is H.

Proof:

* Suppose there are two distinct messages M and M' such that H(M) = H(M') (ie, a collision) - **1**
* Chain for H(M) = IV, H<sub>0</sub>, H<sub>1</sub>, ..., H<sub>t</sub>, H<sub>t+1</sub>
* Chain for H(M') = IV, H<sub>0</sub>', H<sub>1</sub>', ..., H<sub>r</sub>', H<sub>r+1</sub>'
* From **1**, H<sub>t+1</sub> = H<sub>r+1</sub>', ie, h(H<sub>t</sub>, M<sub>t</sub>||PB) = h(H<sub>r</sub>', M<sub>r</sub>'||PB')
* If H<sub>t</sub> != H<sub>r</sub>' OR M<sub>t</sub> != M<sub>r</sub>' OR PB != PB' that's a collision for h and we're done. So lets assume all 3 are equal to each other.
* If PB = PB', then the messages must be of equal length => t = r
* So moving to the previous block we apply the same analysis. Either the arguments to h are equal, or its a collision. h(H<sub>t-1</sub>, M<sub>t-1</sub>) = h(H<sub>t-1</sub>', M<sub>t-1</sub>'). If the arguments are equal, we keep going.
* If we reach the first block and the arguments are still equal, then the entire message is equal. This contradicts the assumption in **1**

Note that this proof depends on the length being encoded in PB.

---

#### Davies-Meyer compresion function

E: K x {0,1}<sup>n</sup> -> {0,1}<sup>n</sup> is a block cipher

The D-M construction is h(H, m) = E(m, H) ⨁ H

<center>![Davies-Meyer](https://upload.wikimedia.org/wikipedia/commons/5/53/Davies-Meyer_hash.svg)</center>

Theorem: If E is an ideal cipher (collection of |K| random permutations), then finding a collision h(H, m) = h(H', m') takes O(2<sup>n/2</sup>) evaluations of E, D. (ie, birthday attack)

---

#### Case study - SHA-256

* Uses Merkle-Damgard construction
* Uses Davies-Meyer compression function
* Block cipher used is SHACAL-2

---

#### Provable compression functions

Its proof is based on the underlying problem being hard to solve.

* Choose a random 2000-bit prime p and random 1 <= u, v < p
* For m, h ∈ {0, 1, ..., p-1} define h(H, m) = u<sup>H</sup>v<sup>m</sup> mod p

Finding a collision for h is as hard as solving "discrete-log" modulo p. The caveat is that its really slow.

---

#### HMAC (Hash-MAC)

<center>![HMAC](http://i.imgur.com/AyF8bP1.png)</center>

Consider each h as a PRF where the message blocks are the keys. No imagine the outputs of the first h block in each chain as k<sub>1</sub> and k<sub>2</sub> respectively. Now its NMAC, except the keys are dependent.

ipad and opad are 512-bit constants specified in the standard. So we need to argue that that h is a PRF even when dependent keys are used. h doesn't need to be collision-resistant, it just needs to be a PRF.

That's why TLS specifies a HMAC based on SHA-1 truncated to 96 bits.

---

#### Verification timing attacks

```
def verify(key, msg, sig_bytes):
  return HMAC(key, msg) == sig_bytes
```

`==` is a byte-by-byte comparison operator, so the code returns as soon as it finds the first byte that's not equal.

Say a verification server takes a (message, tag) pair and returns true/false if its valid/invalid based on the snippet above. To attack such a server, keep a fixed message and guess the tag byte-by-byte.


##### Defense 1

Comparing two arguments should take constant time

```
def verify(key, msg, sig_bytes):
  if len(sig_bytes) != correct_length:
    return false
  result = 0
  for x, y in zip(HMAC(key, msg), sig_bytes):
    result |= ord(x) ^ ord(y)
  return result == 0
```

An optimizing compiler could end that loop if it thinks its the result has been achieved.

##### Defense 2

Compare two different things

```
def verify(key, msg, sig_bytes):
  mac = HMAC(key, msg)
  return HMAC(key, mac) == HMAC(key, sig_bytes)
```

In this case, optimizing compiler won't hurt you
