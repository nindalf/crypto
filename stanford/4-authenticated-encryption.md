Authenticated Encryption
===

**Confidentiality** - semantic security against a chosen plaintext attack. Encryption is secure against eavesdropping only.

**Integrity** - Existential unforgeability under chosen message attack. eg. CBC-MAC, HMAC, PMAC, CW-MAC

**Goal** - Encryption secure against tampering - Confidentiality + Integrity - Authenticated Encryption. The adversary is one who can tamper with traffic, dropping certain packets while injecting others

#### A warning

CPA security cannot guarantee secrecy under active attacks. They should never be used on their own. An attacker can still

* Tamper with a block cipher in CBC mode when you know the plaintext corresponding to a certain block.
* Tamper with packets being sent in CTR mode. By tampering with the CRC and Data fields of the TCP packet and listening for ACKs, its possible to guess the ciphertext. The listener can mistake the attack for poor connectivity. The recipient acts as an oracle.

---

#### Definition

An authenticated encryption system (E, D) is defined as

* E: K x M x N -> C where N is optional
* D: K x C x N -> M ∪ ⟘ (⟘ ∉ M, denotes invalid ciphertext)

To be secure, such a system should provide

1. Semantic security under chosen plaintext attack
2. Ciphertext integrity - it should be impossible for the attacker to create ciphertexts that decrypt properly.


#### Ciphertext integrity

The adversary can submit q messages m<sub>1</sub>,... , m<sub>q</sub> to the challenger. The challenger encrypts these under a key k and returns c ciphertexts c<sub>1</sub>,... , c<sub>q</sub>. The adversary constructs and sends back a ciphertext c, to which the challenger responds with

* b = 1 if D(k, c) != ⟘ and c ∉ {c<sub>1</sub>,... , c<sub>q</sub>}, indicating the adversary won
* b = 0 otherwise, indicating the adversary lost

Defintion of security - (E, D) has ciphertext integrity if for all "efficient" aversaries A, Adv<sub>CI</sub>[A, E] = Pr[Challenger outputs 1] is "negligible"

---

#### Implications

Chosen Ciphertext game: Adversary submits two messages one block m<sub>0</sub> and m<sub>1</sub>. He gets back (IV, c<sub>b</sub>, he needs to guess which he got. He can submit a new ciphertext c' and ask for a decryption. Based on what he gets, he has to guess if the message was originally encrypted by the challenger. For CBC mode, its trivial to create c' such that the IV is IV ⨁ 1. This is a new, valid ciphertext and the corresponding plaintext is m<sub>b</sub> ⨁ 1. The adversary can thus guess b with advantage 1.

**Authenticated encryption** => Chosen ciphertext security.

Theorem: Let (E, D) be a cipher that provides authenticated encryption. Then (E, D) is CCA secure. In particular, for any q-query adversary A, there exists an adversary B<sub>1</sub>, B<sub>2</sub> s.t.

Adv<sub>CCA</sub> <= 2q Adv<sub>CI</sub>[B<sub>1</sub>, E] + Adv<sub>CI</sub>[B<sub>2</sub>, E]

1. Authenticity - the attacker cannot fool Bob by impersonating Alice, since he doesn't have the key k.
2. Secure against chosen ciphertext attacks, because it is not possible to create valid ciphertexts
3. It is still vulnerable to
  * Replay attacks
  * Side channel attacks

---

#### Constructing an Authenticated Encryption scheme

In the bad old days (pre-2000), crypto libraries provided CPA-secure functions (AES-CBC) and MAC functions (HMAC) and each developer could have fun mixing and matching. Not all combinations provided AE.


<center>![Three schemes of AE](http://i.imgur.com/lc3j8zq.png)</center>

* SSL - MAC(m) then encrypt
* IPsec - encrypt *then* MAC(c)
* SSH - encrypt *and* MAC(m)

Which scheme is best?

* SSL's scheme is not perfect. It is vulnerable to CCA because of possible weird interactions between the MAC and the encryption scheme. However, in the case of rand-CTR or rand-CBC mode, MAC-then-encrypt provides AE. For rand-CTR, even one-time MAC is sufficient.
* SSH's scheme is not recommended. Its perfectly ok in general for a tag to leak bits of the message, but in this case, it would break CPA security. Although SSH itself is not broken, this scheme isn't good.
* IPsec's scheme is best, and always correct.

Authenticated Encryption with Associated Data (AEAD) - only a part of the message needs to be encrypted, but the entire message needs to be authenticated. Here are a few modes that implement this, along with the associated speed on Prof Boneh's machine.

1. GCM (Galois/Counter mode) - CTR-mode encryption then Carter-Wegman MAC - 108 MBps
2. CCM (Counter with CBC MAC) - CBC-MAC then CTR-mode encryption - 61 MBps
3. EAX (couldn't find the expansion) - CTR-mode encryption then CMAC - 61 MBps

All of these are nonce-based. Remember, the nonce need not be random and its ok to use a counter as a nonce. But the pair (key, nonce) should never, ever repeat.

OCB is a one-pass mode (encrypt and MAC together) that's faster than any of the 3 modes (129 MBps), but is encumbered by patents.

---

#### TLS Case study

Communication between a browser b and a server s

* There are 2 unidirectional keys k<sub>b->s</sub> and k<sub>s->b</sub>. Both parties know both the keys.
* The browser uses k<sub>b->s</sub> to encrypt data before sending and k<sub>s->b</sub> to decrypt received data.
* There are 2 64-bit counters ctr<sub>b->s</sub> and ctr<sub>s->b</sub> that are initialised to 0 when the session starts. Since both the server and the client maintain this state, TLS is stateful encryption
* The appropriate counter is incremented when a record is sent or received. These counters are meant to protect against replay attacks
* MAC-then-encrypt. The MAC is HMAC-SHA-1 and the encryption scheme is CBC AES-128.

<center>![TLS packet](http://i.imgur.com/zlIuDsh.png)</center>

**Browser side encryption**:

1. tag <- S(k<sub>mac</sub>, [++ctr<sub>b->s</sub> || header || data]).
2. pad [header || data || tag] to AES block size.
3. CBC encrypt with k<sub>enc</sub> with new random IV.
4. Prepend plaintext header (type || version || packet length).

Note that k<sub>b->s</sub> = (k<sub>mac</sub>, k<sub>enc</sub>). So there are 4 keys in all, all of which are known to both parties. Also, the value of the counter isn't sent, because the server knows the current value of the counter.

**Server side decryption**:

1. CBC decrypt with k<sub>enc</sub>.
2. Strip the padding. Send bad_record_mac if invalid. (ie, ⟘)
3. Verify the tag - V(k<sub>mac</sub>, [++ctr<sub>b->s</sub> || header || data], tag). Send bad_record_mac if invalid.

**Security features**:

1. If a packet is resent by an attacker, the tag would no longer be valid. Sending the counter doesn't increase the length of the ciphertext either, so its a very neat solution.
2. By only sending ⟘ in case of bad pad OR bad MAC, it tells the attacker nothing. If he gets more specific error information, it could be used to break the protocol. General rule: If decryption fails, *never* explain why.

**Bugs in previous version**:

1. IV for next record would be ciphertext of the current record. This isn't CPA secure (pre 1.1)
2. Padding oracle - it would send decryption_failed in case of bad pad and bad_record_mac in case of invalid MAC

---

#### 802.11b WEP - how not to do it

Previous vulnerabilities discussed

* It becomes a 2-time pad after every 16m frames.
* The seeds used for RC4 were highly related. RC4 wasn't designed to accept related keys

Yet another vulnerability - the crc included in the frame was too linear. ∀ m, p: CRC(m⨁p) = CRC(m)⨁F(p), where F is a well-known function. It is trivial to modify the ciphertext and also modify the CRC such that it is valid for the tampered plaintext

Solution - use a cryptographic MAC, not an ad-hoc solution like Cyclic Redundancy Check (CRC).

---

#### Padding Oracle attack

This is an example of a chosen ciphertext attack. If the attacker can differentiate between the two errors (invalid_mac, invalid_pad), the attacker submits a ciphertext and learns if the last bytes of the plaintext are a valid pad. He modifies the ciphertext and guesses the plaintext byte by byte.

Even if the server sends the same response (⟘) in both cases, a timing attack is still possible. Since the padding is checked before the mac and verfication takes some time, the attacker can differentiate betweent the two errors. In OpenSSL 0.9.7a, the response for a bad padding was received in 21ms on average and response for a bad mac was received in 23ms

**Steps**:

1. Start with ciphertext block i, throw away the blocks after that.
2. Guess a value g for the last byte of block i. Change the last byte of ciphertext block c[i-1] to (last-byte ⨁ g ⨁ 01) where 01 is the valid padding for a 15-byte long message
3. If the guess is correct, the last byte of plaintext m[i] becomes g ⨁ g ⨁ 01 = 01 and the server tells us that the pad is valid. The max number of guesses is 256 and on average it should take 128 guesses

Padding oracle is difficult to pull off on TLS because when the server receives a message with invalid_mac or invalid_pad, it tears down the connection and renogiates the key.

It is however, possible to pull off this attack on IMAP servers.

**Lessons**:

* Encrypt-then-MAC would have completely avoided this problem. MAC is checked first and discarded if invalid.
* MAC-then-CBC provides AE, but a padding oracle destroys it.

---

#### Attacking non-atomic decryption

<center>![SSH binary packet](http://i.imgur.com/voz0103.png)</center>

SSH uses encrypt-*and*-MAC. Decryption procedure:

1. Decrypt packet field length only (!)
2. Read as many packets as the length specifies
3. Decrypt remaining ciphertext blocks
4. Check MAC tag and see if the error response is valid

**How to exploit this**:

1. We expect that the server will send us a MAC error only if it reads the correct number of packets from the first decrypted block.
2. Say we have a ciphertext block. We send that to the server as the first block, corresponding to packet len.
3. We feed in data 1 byte at a time until we get a MAC error. When we do, we know that the first 5 bytes of the block we sent were correct.
4. We keep trying bytes in this manner

**Lessons**:

1. Non-atomic decryption
2. Length field decrypted and used before it is authenticated

**Ways to redesign this**:

1. Send the length field unencrypted, but MAC-ed.
2. Add a MAC of (seq-num, length) right after the len field.

---

#### If you need to design your own encrypted authentication scheme

Steps:

1. Stop
2. Don't do this
3. Use GCM, CCM or EAX instead

But actual pointers in case you're doing it anyway

1. Use encrypt-then-MAC
2. Don't use length field before the length field is authenticated (like SSH did)
3. Don't use *any* decrypted field before its authenticated

---

#### Papers

1. The Order of Encryption and Authentication for Protecting Communications - Krawczyk
2. Authenticated Encryption with Associated Data - Rogaway
3. Password Interception in an SSL/TLS channel (ie, padding oracle) - Canvel, Hiltgen, Vaudenay, Vuagnoux
4. Plaintext recovery attacks against SSH - Albrech, Paterson, Watson
5. Problem areas for IP security protocols (schemes that use CPA security and don't add integrity) - Bellovin
