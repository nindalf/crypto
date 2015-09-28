Public Key Encryption
===

A public key encryption system is a triple of algorithms (G, E, D).

* G() - a randomized algorithm that outputs a key pair (pk, sk) (public key, secret key)
* E(pk, m) - Encrypts the message m ∈ M under the private key and generates a ciphertext c ∈ C
* D(sk, c) - Decrypts the ciphertext c ∈ C using the secret key to recover the message m or ⟘

The triple is consistent. ∀(pk, sk) output by G and ∀ m ∈ M:  D(sk, E(pk, m)) = m

Its useful for

* Session setup, say between a web server and a web browser
* Non-interactive applications
  1. Email - encrypt the message with the recipient's public key
  2. Encrypted filesystems - encrypt a file with a symmetric key and include in the header copies of the symmetric key encrypted with the public keys of the people who have access. Such a scheme accommodates key escrow services - where one of the public keys used is k<sub>escrow</sub>

---

#### Security

**Example of active attack**:

Scenario: Bob sends the gmail server a message for Caroline(caroline@gmail.com) encrypted with CTR mode. The attacker intercepts the message and modifies it. He knows that the first few bytes of the message is "to:caroline@". He trivially changes that to "to:attacker@". The plaintext gets sent to him by the gmail server.

**Chosen ciphertext security**:

The game for encryption scheme (G, E, D) is defined thus:

* The challenger is implementing experiment "b" = {0, 1}.
* The challenger generates (pk, sk) and sends the adversary pk.
* The adversary enters CCA phase 1 and submits a series of ciphertexts and asks for the plaintexts.
* The adversary then submits 2 messages m<sub>0</sub> and m<sub>1</sub> where |m<sub>0</sub>| = |m<sub>1</sub>|. The challenger returns the ciphertext c <- E(pk, m<sub>b</sub>).
* The adversary enters CCA phase 1 and submits a series of ciphertexts and asks for the plaintexts. The only restriction is that he can't submit the ciphertext c.

(G, E, D) is Chosen Ciphertext Attack (CCA) secure if for all efficient adversaries - Adv<sub>CCA</sub>[A, E] = |Pr[Exp(0)=1] - Pr[Exp(1)=1]| < negligible

This is the correct notion of security for Public Key systems
