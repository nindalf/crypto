Basic Key Exchange
====

#### Trusted 3rd parties

* If there are n users in the world who all wish to communicate with each other.
* Problem - They will require n! keys in total to do so, with every user storing n keys. Storing and using this many keys is not feasible.
* Solution - A trusted 3rd party (TTP). Consider this toy protocol that is secure against eavesdropping.
  1. Alice and Bob share their secret keys k<sub>A</sub> and  k<sub>B</sub> with TTP.
  2. Alice tells the TTP "I want a shared key with Bob".
  3. TTP generates a random key k<sub>AB</sub> and sends E(k<sub>A</sub>, "A, B" || k<sub>AB</sub>) where (E, D) is a CPA secure cipher.
  4. TTP also sends her the "ticket" - E(k<sub>B</sub>, "A, B" || k<sub>AB</sub>).
  5. When communicating with Bob, she sends him the ticket, from which he can extract k<sub>AB</sub>.
  6. Both now share a random key, unrelated to their actual secret keys. They can communicate. An eavesdropper has no way of knowing anything about k<sub>AB</sub>.
* Pros of TTP
  1. Simple, requiring only symmetric key encryption.
  2. Symmetric key encryption is fast.
* Cons of TTP
  1. The TTP is needed for every exchange. If its offline, no communication is possible.
  2. The TTP knows *all* session keys.
  3. Vulnerable to replay attacks (an active attacker). Copy the bytes sent by Alice to Bob and send them again later.
* Solution: Generate shared keys without an online TTP

---

#### Merkle Puzzles

It is possible to exchange keys without a TTP, using only block ciphers and hash functions (what we've learnt so far). It is inefficient, however.

A puzzle is a problem that can be solved with some effort. For example, this puzzle:

* E(k, m) is a symmetric cipher with k ∈ {0,1}<sup>128</sup>
* puzzle(P) = E(P, "message") where P = 0<sup>96</sup> || b<sub>1</sub>...b<sub>32</sub>
* Goal - finding P by trying all 2<sup>32</sup> possibilities.

Procedure for the Merkle Puzzle

1. Alice generates 2<sup>32</sup> such puzzles in O(N) time.
2. For i = 1, ..., 2<sup>32</sup> choose random P<sub>i</sub> ∈ {0,1}<sup>32</sup> and x<sub>i</sub>, k<sub>i</sub> ∈ {0,1}<sup>128</sup>, set puzzle<sub>i</sub> <- E(0<sup>96</sup> || P<sub>i</sub>, "Puzzle x<sub>i</sub>" || k<sub>i</sub>)
3. Alice sends all the puzzles to Bob, in a random order.
4. Bob randomly chooses one of the puzzles - puzzle<sub>j</sub> solves in at most 2<sup>32</sup> iterations (in O(N) time). He obtains (x<sub>j</sub>, k<sub>j</sub>)
5. He sends her x<sub>j</sub> and both use k<sub>j</sub> as the shared secret

For an eavesdropper to break this, he needs to do O(N<sup>2</sup>) work. This is decent, but Alice needs to send a *lot* of data to Bob (on the order of gigabytes) and both need to do 2<sup>32</sup> work. In return, they get a scheme that can be broken in only 2<sup>64</sup> iterations, which is doable. It would be better to have security up to 2<sup>128</sup> but asking Alice and Bob to do 2<sup>64</sup> work and also send that much data one way is impossible. Roughly speaking, such a quadratic gap is the best possible using symmetric ciphers/hash functions.

That's why this isn't used in practice. However there is a good idea here - the participants had to some work to set up the scheme but the attacker had to do much more to break it.

---

#### Diffie-Hellman protocol

Goal - an exponential gap between the attacker's work and the participant's work.

An informal explanation of Diffie-Hellman

1. Fix a large prime p (eg. 600 digits, or 2000 bits) forever
2. Fix an integer g in {0, 1, ...., p} forever
3. Alice chooses a in {0, 1, ...., p}. She computes A <- `g<sup>a</sup> (mod p)` efficiently and sends A to Bob
4. Bob does something similar with a number b. He computes B <- `g<sup>b</sup> (mod p)` and sends B to Alice
5. Alice computes B<sup>a</sup> and Bob computes A<sup>b</sup>. Both are equal to g<sup>ab</sup> (mod p)

**Security**: Its easy to see that Alice and Bob now share a value. What's difficult is proving that an eavesdropper (Eve) can't calculate that value (g<sup>ab</sup>) despite knowing p, g, A, B. How hard is it to compute DH<sub>g</sub>(g<sup>a</sup>, g<sup>b</sup>) (mod p)?

The best known algorithm to compute the DH function is the General Number Field Sieve, an algo used to factor integers larger than 100 digits. Its running time is sub-exponential - e<sup>O(cubrt(n))</sup> (Exponential would be e<sup>n</sup>). To ensure security, the modulus size should be 15360 for a 256-bit key, 3072 for a 128-bit key. 15360 is much too large to work with. Thus, DH is modified to work with Elliptic Curves, which would yield moduluses that are 2x the size of the keys.

**Insecure against Man-in-the-Middle**: A MitM receives A from from Alice and sends A' to Bob. She receives B from Bob and sends Alice B'. Alice computes g<sup>ab'</sup> and Bob computes g<sup>a'b</sup>. The MitM knows both. Alice sends a message encrypted with g<sup>ab'</sup>, Eve decrypts it and encrypts it with g<sup>a'b</sup> and sends it to Bob.

---

#### Public Key Encryption

A public key encryption system is a triple of algorithms (G, E, D).

* G() - a randomized algorithm that outputs a key pair (pk, sk) (public key, secret key)
* E(pk, m) - Encrypts the message m ∈ M under the private key and generates a ciphertext c ∈ C
* D(sk, c) - Decrypts the ciphertext c ∈ C using the secret key to recover the message m or ⟘

The triple is consistent. ∀(pk, sk) output by G and ∀ m ∈ M:  D(sk, E(pk, m)) = m

**Semantic security**:

Chosen plaintext security makes no sense in a public key encryption system because the adversary already knows the public key. He can generate all the ciphertexts he wants. The adversary submits 2 plaintexts m<sub>0</sub> and m<sub>1</sub> of equal length and gets ciphertext c <- E(pk, m<sub>b</sub>). He needs to guess which message was encrypted.

The system E = (G, E, D) is semantically secure against *eavesdropping* if the all efficient adversaries A cannot distinguish between the 2 experiments.

Adv<sub>SS</sub>[A, E] = |Pr[Exp(0)=1] - Pr[Exp(1)=1]| < negligible

Note that in public key encryption, one-time security implies many-time security because the adversary has the public key and can make as many ciphertexts as he pleases.

**Key exchange**:

1. Alice sends Bob her public key
2. Bob encrypts a random 128-bit key with the public key and returns the ciphertext
3. Alice decrypts the ciphertext using her secret key, recovering the 128-bit key

This is still vulnerable to a MitM attack.
