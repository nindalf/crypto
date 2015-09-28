Discrete Probability
===

In the old days crypto didn't have proofs and it sucked. Modern cryptography has been developed as a rigorous science and new methods need to be accompanied by a proof of security. For this we need discrete probability.

Further reading - https://en.wikibooks.org/wiki/High_School_Mathematics_Extensions/Discrete_Probability

Mathematical symbols copied from [wiki page](https://en.wikipedia.org/wiki/Mathematical_operators_and_symbols_in_Unicode). Some symbols used are ∑ ∏ ∀ ∈ (belongs to) ∉ ⊆ ∪ ⨁ ∄ ∃ ϵ (epsilon) ≈ ⟘ 𝜑

#### Basics

* Defined over U: finite set (eg. U={00, 01, 10, 11})
* Probability distribution P over U is a function P:U -> [0,1]
* P assigns every element in U a number between 0 and 1 such that ∑P(x) = 1 (x ∈ U). The number assigned to that element is called the probability of of that element.
* Since U is finite, we can write down the whole set along with corresponding probabilities and represent it as a vector

#### Some distributions

* Uniform distribution - all elements of set have equal probability
* Point distribution - one element has probability 1. Rest have probability 0

#### Event

* A subset of the universe U, ie, A ⊆ U
* The probability of it occurring is between [0, 1]
* The union bound - Probability that either event 1 (A1) occurs OR event 2 (A2) occurs is by union - Pr[A1 ∪ A2] <= Pr[A1] + Pr[A2]
* If the intersection of A1 and A2 is null, ie the 2 events are disjoint, ie, A1 ∩ A2 = ϕ, then Pr[A1 ∪ A2] = Pr[A1] + Pr[A2]
* Independence - Events A1 and A2 are independent if one event happening tells you nothing about whether the other event occurred. Probability of both events happening = Pr[A1 and A2] = Pr[A1] * Pr[A2]

#### Random variables

* A random variable X is a function X:U -> V. X is a function, U is the universe and it maps into V, where it takes its values.
* Example. X: {0,1}^n -> {0,1}. Universe is all n-bit binary strings and it maps into a 1 bit value. Here the function could be lsb(y)
* More generally: rand var X induces a distribution on V. Pr[X=v] := Pr[X^-1 (v)]
* Independence - random variables X and Y are independent if ∀ a, b ∈ V: Pr[X=a and Y=b] = Pr[X=a] * Pr[Y=b]
* Example of independent RV - XOR ⨁. If X is a random variable over {0,1}^n and Y is an independent uniform random variable over {0,1}^n, then the result Z is a uniform random variable on {0,1}^n. This theorem is important for cryptography

#### Uniform random variable

* Let U = {0,1}^n
* r is a uniform random variable such that Pr[r=a] = 1/|U| where a ∈ U (|U| is the size of U)

#### Randomized algorithms

* Deterministic algorithm: y <- A(m). We get the same output every time we run the function over the input message m.
* Randomized algorithm: y <- A(m, r) where r is a random variable. Every time we run y, a new r is generated and we get a different output.
* If you think about it, the second y is a random variable itself. An example of this would be encrypting a message over a key.

#### The Birthday Paradox

Let r1, .., rn ∈ U be n independent, indentically distributed random variables

If you sample n = 1.2 * sqrt(|U|) times, then the probability that there exists two indices i, j such that ri = rj is greater than half.  

Example. Sample n= 2^64 elements from the set of all 2^128 length messages. Two sampled messages are likely to be the same. The probability converges very quickly to 1 for n greater than sqrt(|U|)

For 2 people sharing the same birthday, the probability is 0.5 for n=23 people.

![birthday distribution](https://upload.wikimedia.org/wikipedia/commons/c/ca/Birthday_paradox_probability.svg)
