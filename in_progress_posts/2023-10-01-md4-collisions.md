---
layout: post
title: "Generating MD4 Collisions"
author: Anton Kueltz
tag: practical-exploit
---

One thing in cryptography that is always fun is putting theory into practice. A lot
of people probably know not to use the MD4 hash function (or the more popular MD5 for
that matter) for any cryptographic applications. I would wager that less people out there
have actually generated MD4 collisions themselves. In this post we'll look at how to generate
MD4 collisions using the attack from
[Wang et al](https://iacr.org/archive/eurocrypt2005/34940001/34940001.pdf).

# Overview

We'll write the core of our code in C for performance and then we'll wrap that C code as
a python C extension and use python as the language for driving the high level collision
logic. I would recommend reading through sections 3 and 4 from the Wang et al paper to get
an idea of how the attack works. I will summarize below -
1. Randomly sample a 512 bit message `M` to use as our first input to MD4.
2. "Massage" the message `M` such that it meets criteria for a collision candidate.
3. Generate `M'` using the updated `M` from the above step.
4. Check if `md4(M) == md4(M')`, if so terminate and return `M` and `M'` as a collision pair.
5. Return to step 1.

The core of the attack is of course in how we "massage" the message `M` . We'll get into that
in the sections below.

# Preliminary Functions

We need to implement a couple preliminary functions that come from the internals of the
[MD4 algorithm](https://datatracker.ietf.org/doc/html/rfc1186). They are helpfully described
in the Wang et al paper in section 2.1 "MD4 Algorithm". The first are a pair of nonlinear
Boolean functions

$$F(X, Y, Z) = (X \land Y) \lor (\lnot X \land Z)\\G(X, Y, Z) = (X \land Y) \lor (X \land Y) \lor (Y \land Z)$$

We can simply translate these to C macros
```c
#define F(x, y ,z) ((x & y) | (~x & z))
#define G(x, y, z) ((x & y) | (x & z) | (y & z))
```

We also need to implement bitwise rotation to the left for 32 bit inputs. Note that this is similar
to a bit shift to the left, except that values $$\geq 2^{32}$$ wrap back around to the lower bits. As
an example, if we left rotate `11010010` by 2 we would get `01001011` (the 2 highest order bits wrap back
around and become the 2 lowest order bits). Defining this as a C macro, where `x` is a `uint32_t` and `n`
is the number of bits to left rotate by
```c
#define LROT(x, n) ((x << n) | (x >> (32 - n)))
```

Using the above we can now implement the step operation for each round. The MD4 algorithm has 3 rounds,
but we only need the step operation for rounds 1 and 2. A round is (in simplified terms) 16 applications
of the round's step function to the internal state of the algorithm. The first two rounds step functions are

$$\phi_0(a, b, c, d, m_k, s) = ((a + F (b, c, d) + m_k) \bmod 2^{32}) \lll s\\\phi_1(a, b, c, d, m_k, s) = ((a + G(b, c, d) + m_k + \texttt{0x5a827999})  \bmod 2^{32}) \lll s$$

Note that $$m_k$$ refers to the "kth" 32 bit block of the input message `M`. Recall that we have 16 applications of
the step functon per round and that `M` is 512 (= 32 * 16) bits long. We can again translate these to C macros
```c
#define PHI0(a, b, c, d, m, s) (LROT(((a + F(b, c, d) + m) & 0xffffffffu), s))
#define PHI1(a, b, c, d, m, s) (LROT(((a + G(b, c, d) + m + 0x5a827999u) & 0xffffffffu), s))
```

In our macros we assume that the caller gives us the correct block of `M` and simply use the `m` variable to represent
that block.

# Massaging the Message
This is where things get tricky and where careful attentionto Wang et al and the MD4 spec is required.
From Section 2 "MD4 Algorithm" in the spec, specifically "Step 4. Process message in 16-word blocks"
(Recall that A, B, C and D are the internal state of MD4)

<pre>
[Round 1]
  Let [A B C D i s] denote the operation
        A = (A + f(B,C,D) + X[i]) <<< s  .
  Do the following 16 operations:
        [A B C D 0 3]
</pre>

We then have, from "Table 6. A Set of Sufficient Conditions for Collisions of MD4" in Wang et al, that $$a_{1,7} = b_{0,7}$$.
This means that after $$a$$ (= A in the spec nomenclature) has been updated once (hence the $$1$$ subscript in $$a_1$$)
it's 7th bit should be equal to the 7th bit of $$b_0$$ (= the initial state of B). We then need to derive the message block
that would result in the modified internal state (where $$a_{1,7} = b_{0,7}$$). So we need to perform the following steps
1. Compute $$a_1 = ((a_0 + F (b_0, c_0, d_0) + m_0) \bmod 2^{32}) \lll 3$$.
1. Compute $$a'_1$$ such that $$a'_{1,7} = b_{0,7}$$ (and for $$i \neq 7$$ we have $$a'_{1, i} = a_{1, i}$$).
1. Derive an $$m'_0$$ such that $$a'_1 = ((a_0 + F (b_0, c_0, d_0) + m'_0) \bmod 2^{32}) \lll 3$$
   * This works out to $$m'_0 = ((a_0 \ggg 3) - a'_1 - F(b_0, c_0, d_0)) \bmod 2^{32}$$

The last step can be generalized, for round one (aka the $phi_0$ function) to the following formula, where $$x$$ is the current
internal state after step $$i$$ and $$x-1$$ was the internal state before step $$i$$

$$m'_i = ((a_{x-1} \ggg s) - a'_{x} - F(b_{x-1}, c_{x-1}, d_{x-1})) \bmod 2^{32}$$

We can then convert this to a macro (which we call `INV0` as it is sort of an inverse of the `PHI0` macro)
```c
#define RROT(x, n) ((x >> n) | (x << (32 - n)))
#define INV0(x, a, b, c, d, s) ((RROT(x, s) - a - F(b, c, d)) & 0xffffffffu)
```
Note that in the above we use `x` to refer to $$a'_x$$ and `a` to refer to $$a_{x-1}$$. The following is then how we would massage
the message `M` for round 1 step 1 (`a, b, c, d, x` are of type `uint32_t`)
```c
x = a;
a = PHI0(a, b, c, d, m[0], 3);
a = EQ(a, b, 7);
m[0] = INV0(a, x, b, c, d, 3);
```

Note we use an additional `EQ` macro here, which takes arguments `x, y, i` and sets bit `i` of `x` to the same value as bit `i`
of `y`
```c
#define SET(x, i) (x | (1u << (i - 1)))
#define CLR(x, i) (x & ~((1u << (i - 1))))
#define EQ(x, y, i) (((y >> (i - 1)) & 1) ? SET(x, i) : CLR(x, i))
```

We now have a generalized algorithm for generating a massged version of `M`
1. Apply `PHI0` to the arguments specified in the MD4 spec based on the round and step.
1. Modify the output of `PHI0` to meet the conditions given in Table 6 from Wang et al.
1. Apply `INV0` to get the massaged message block that produces the internal MD4 state specified in Table 6.
1. Set the corresponding block in `M` to the massaged message block.

You can check out the Appendix for a full implementation of how the message is massaged.

# Multi-Step Modification
Things get more complicated in round 2. Not only do we have to apply the above process, but we also need to take care to
keep the already modified blocks from round 1 in a state that does not invalidate the work from round 1 (recall that the
message is 16 blocks of 32 bits, so each round modifies each block). This is where, frankly, my understanding of the
attack tops out and I needed to resort to simply replicating Table 1 and Table 2 in Wang et al without being able to
fully grok the theory behind the correction logic. The implementation is below
```c
    // ROUND 2 STEP 17
    x = a;
    a = PHI1(a, b, c, d, m[0], 3);
    // modifications from Table 6
    a = EQ(a, c, 19);
    a = SET(a, 26);
    a = CLR(a, 27);
    a = SET(a, 29);
    a = SET(a, 32);
    m[0] = INV1(a, x, b, c, d, 3);
    // multi message correction from Table 1
    uint32_t a1 = PHI0(a0, b0, c0, d0, m[0], 3);
    m[1] = INV0(d1, d0, a1, b0, c0, 7);
    m[2] = INV0(c1, c0, d1, a1, b0, 11);
    m[3] = INV0(b1, b0, c1, d1, a1, 19);
    m[4] = INV0(a2, a1, b1, c1, d1, 3);

    // ROUND 2 STEP 18
    x = d;
    d = PHI1(d, a, b, c, m[4], 5);
    // modifications from Table 6
    d = EQ(d, a, 19);
    d = EQ(d, b, 26);
    d = EQ(d, b, 27);
    d = EQ(d, b, 29);
    d = EQ(d, b, 32);
    m[4] = INV1(d, x, a, b, c, 5);
    // multi message correction from Table 2
    a2 = PHI0(a1, b1, c1, d1, m[4], 3);
    m[5] = INV0(d2, d1, a2, b1, c1, 7);
    m[6] = INV0(c2, c1, d2, a2, b1, 11);
    m[7] = INV0(b2, b1, c2, d2, a2, 19);
    m[8] = INV0(a3, a2, b2, c2, d2, 3);
```

This is also why we do not implement $$\phi_2$$ or $$H(X, Y, Z)$$ from the MD4 spec. The complexity of doing the correction by
round 3 is high enough that implementing it correctly is beyond the scope of this particular implementation. Luckily, if we
implement all the modifications from Table 6 up to $$d_5$$ we still end up with a perfectly practical and efficient attack.

# Generating MD4 Collisions

Wang et al give a computational complexity in the $$2^{-2} ~ 2^{-6}$$ range. Since we do not implement all modifications from
later rounds our attack will be a less efficient. Either way, the attack is probabalistic and will not always work for random `M`.
As such, we need to have some control flow code to generate random messages `M`, derive `M'`, check if they are a collision, and
loop if the are not. We write this in python for simplicity since this part doesn't need to be terribly efficient

```python
from binascii import hexlify
from hashlib import new as new_hash
from os import urandom
from struct import pack, unpack
from sys import stdout
from typing import List


def md4_collider():
    collision = False

    i = 0
    while not collision:
        i += 1
        if i % 1000 == 0:
            stdout.write('.')
            stdout.flush()

        M: bytes = urandom(64)  # 64 * 8 = 512 bits
        m: List[int] = _message_blocks(M)
        m = massage_message(m)

        m_ = m[:]
        m_[1] = (m[1] + 2 ** 31) & 0xffffffff
        m_[2] = (m[2] + (2 ** 31 - 2 ** 28)) & 0xffffffff
        m_[12] = (m[12] - 2 ** 16) & 0xffffffff

        M = _form_message(m)
        M_ = _form_message(m_)

        collision = _md4_hash(M) == _md4_hash(M_)

    return f'Found MD4 collision for messages\n' \
           f'M = {_format_msg(M)}\n' \
           f'M\' = {_format_msg(M_)}\n' \
           f'h = {hexlify(_md4_hash(M_)).decode()}'


def _md4_hash(m: bytes) -> bytes:
    return new_hash('md4', m).digest()


def _message_blocks(M: bytes) -> List[int]:
    blocks = []
    for i in range(0, 64, 4):
        (block,) = unpack('<L', M[i:i + 4])
        blocks.append(block)
    return blocks


def _form_message(blocks: List[int]) -> bytes:
    s = b''
    for block in blocks:
        s += pack('<L', block)
    return s


if __name__ == '__main__':
    md4_collider()
```

# Appendix: Complete Implementation

```c
#include <stdint.h>

#define F(x, y ,z) ((x & y) | (~x & z))
#define G(x, y, z) ((x & y) | (x & z) | (y & z))

#define LROT(x, n) ((x << n) | (x >> (32 - n)))
#define RROT(x, n) ((x >> n) | (x << (32 - n)))

#define PHI0(a, b, c, d, m, s) (LROT(((a + F(b, c, d) + m) & 0xffffffffu), s))
#define INV0(x, a, b, c, d, s) ((RROT(x, s) - a - F(b, c, d)) & 0xffffffffu)
#define PHI1(a, b, c, d, m, s) (LROT(((a + G(b, c, d) + m + 0x5a827999u) & 0xffffffffu), s))
#define INV1(x, a, b, c, d, s) ((RROT(x, s) - a - G(b, c, d) - 0x5a827999u) & 0xffffffffu)

#define SET(x, i) (x | (1u << (i - 1)))
#define CLR(x, i) (x & ~((1u << (i - 1))))
#define EQ(x, y, i) (((y >> (i - 1)) & 1) ? SET(x, i) : CLR(x, i))

const uint32_t IV[4] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u};

void massageMessage(uint32_t * m) {
    uint32_t a0 = IV[0], b0 = IV[1], c0 = IV[2], d0 = IV[3];
    uint32_t a = a0, b = b0, c = c0, d = d0;
    // we need to track the chaining values below for multi message corrections
    uint32_t a2, a3, b1, b2, c1, c2, d1, d2, x;

    // ROUND 1 STEP 1
    x = a;
    a = PHI0(a, b, c, d, m[0], 3);
    a = EQ(a, b, 7);
    m[0] = INV0(a, x, b, c, d, 3);

    // ROUND 1 STEP 2
    x = d;
    d = PHI0(d, a, b, c, m[1], 7);
    d = CLR(d, 7);
    d = EQ(d, a, 8);
    d = EQ(d, a, 11);
    m[1] = INV0(d, x, a, b, c, 7);
    d1 = d;

    // ROUND 1 STEP 3
    x = c;
    c = PHI0(c, d, a, b, m[2], 11);
    c = SET(c, 7);
    c = SET(c, 8);
    c = CLR(c, 11);
    c = EQ(c, d, 26);
    m[2] = INV0(c, x, d, a, b, 11);
    c1 = c;

    // ROUND 1 STEP 4
    x = b;
    b = PHI0(b, c, d, a, m[3], 19);
    b = SET(b, 7);
    b = CLR(b, 8);
    b = CLR(b, 11);
    b = CLR(b, 26);
    m[3] = INV0(b, x, c, d, a, 19);
    b1 = b;

    // ROUND 1 STEP 5
    x = a;
    a = PHI0(a, b, c, d, m[4], 3);
    a = SET(a, 8);
    a = SET(a, 11);
    a = CLR(a, 26);
    a = EQ(a, b, 14);
    m[4] = INV0(a, x, b, c, d, 3);
    a2 = a;

    // ROUND 1 STEP 6
    x = d;
    d = PHI0(d, a, b, c, m[5], 7);
    d = CLR(d, 14);
    d = EQ(d, a, 19);
    d = EQ(d, a, 20);
    d = EQ(d, a, 21);
    d = EQ(d, a, 22);
    d = SET(d, 26);
    m[5] = INV0(d, x, a, b, c, 7);
    d2 = d;

    // ROUND 1 STEP 7
    x = c;
    c = PHI0(c, d, a, b, m[6], 11);
    c = EQ(c, d, 13);
    c = CLR(c, 14);
    c = EQ(c, d, 15);
    c = CLR(c, 19);
    c = CLR(c, 20);
    c = SET(c, 21);
    c = CLR(c, 22);
    m[6] = INV0(c, x, d, a, b, 11);
    c2 = c;

    // ROUND 1 STEP 8
    x = b;
    b = PHI0(b, c, d, a, m[7], 19);
    b = SET(b, 13);
    b = SET(b, 14);
    b = CLR(b, 15);
    b = EQ(b, c, 17);
    b = CLR(b, 19);
    b = CLR(b, 20);
    b = CLR(b, 21);
    b = CLR(b, 22);
    m[7] = INV0(b, x, c, d, a, 19);
    b2 = b;

    // ROUND 1 STEP 9
    x = a;
    a = PHI0(a, b, c, d, m[8], 3);
    a = SET(a, 13);
    a = SET(a, 14);
    a = SET(a, 15);
    a = CLR(a, 17);
    a = CLR(a, 19);
    a = CLR(a, 20);
    a = CLR(a, 21);
    a = EQ(a, b, 23);
    a = SET(a, 22);
    a = EQ(a, b, 26);
    m[8] = INV0(a, x, b, c, d, 3);
    a3 = a;

    // ROUND 1 STEP 10
    x = d;
    d = PHI0(d, a, b, c, m[9], 7);
    d = SET(d, 13);
    d = SET(d, 14);
    d = SET(d, 15);
    d = CLR(d, 17);
    d = CLR(d, 20);
    d = SET(d, 21);
    d = SET(d, 22);
    d = CLR(d, 23);
    d = SET(d, 26);
    d = EQ(d, a, 30);
    m[9] = INV0(d, x, a, b, c, 7);

    // ROUND 1 STEP 11
    x = c;
    c = PHI0(c, d, a, b, m[10], 11);
    c = SET(c, 17);
    c = CLR(c, 20);
    c = CLR(c, 21);
    c = CLR(c, 22);
    c = CLR(c, 23);
    c = CLR(c, 26);
    c = SET(c, 30);
    c = EQ(c, d, 32);
    m[10] = INV0(c, x, d, a, b, 11);

    // ROUND 1 STEP 12
    x = b;
    b = PHI0(b, c, d, a, m[11], 19);
    b = CLR(b, 20);
    b = SET(b, 21);
    b = SET(b, 22);
    b = EQ(b, c, 23);
    b = SET(b, 26);
    b = CLR(b, 30);
    b = CLR(b, 32);
    m[11] = INV0(b, x, c, d, a, 19);

    // ROUND 1 STEP 13
    x = a;
    a = PHI0(a, b, c, d, m[12], 3);
    a = CLR(a, 23);
    a = CLR(a, 26);
    a = EQ(a, b, 27);
    a = EQ(a, b, 29);
    a = SET(a, 30);
    a = CLR(a, 32);
    m[12] = INV0(a, x, b, c, d, 3);

    // ROUND 1 STEP 14
    x = d;
    d = PHI0(d, a, b, c, m[13], 7);
    d = CLR(d, 23);
    d = CLR(d, 26);
    d = SET(d, 27);
    d = SET(d, 29);
    d = CLR(d, 30);
    d = SET(d, 32);
    m[13] = INV0(d, x, a, b, c, 7);

    // ROUND 1 STEP 15
    x = c;
    c = PHI0(c, d, a, b, m[14], 11);
    c = EQ(c, d, 19);
    c = SET(c, 23);
    c = SET(c, 26);
    c = CLR(c, 27);
    c = CLR(c, 29);
    c = CLR(c, 30);
    m[14] = INV0(c, x, d, a, b, 11);

    // ROUND 1 STEP 16
    x = b;
    b = PHI0(b, c, d, a, m[15], 19);
    b = CLR(b, 19);
    b = SET(b, 26);
    b = SET(b, 27);
    b = SET(b, 29);
    b = CLR(b, 30);
    m[15] = INV0(b, x, c, d, a, 19);

    // ROUND 2 STEP 17
    x = a;
    a = PHI1(a, b, c, d, m[0], 3);
    // modifications from Table 6
    a = EQ(a, c, 19);
    a = SET(a, 26);
    a = CLR(a, 27);
    a = SET(a, 29);
    a = SET(a, 32);
    m[0] = INV1(a, x, b, c, d, 3);
    // multi message correction from Table 1
    uint32_t a1 = PHI0(a0, b0, c0, d0, m[0], 3);
    m[1] = INV0(d1, d0, a1, b0, c0, 7);
    m[2] = INV0(c1, c0, d1, a1, b0, 11);
    m[3] = INV0(b1, b0, c1, d1, a1, 19);
    m[4] = INV0(a2, a1, b1, c1, d1, 3);

    // ROUND 2 STEP 18
    x = d;
    d = PHI1(d, a, b, c, m[4], 5);
    // modifications from Table 6
    d = EQ(d, a, 19);
    d = EQ(d, b, 26);
    d = EQ(d, b, 27);
    d = EQ(d, b, 29);
    d = EQ(d, b, 32);
    m[4] = INV1(d, x, a, b, c, 5);
    // multi message correction from Table 2
    a2 = PHI0(a1, b1, c1, d1, m[4], 3);
    m[5] = INV0(d2, d1, a2, b1, c1, 7);
    m[6] = INV0(c2, c1, d2, a2, b1, 11);
    m[7] = INV0(b2, b1, c2, d2, a2, 19);
    m[8] = INV0(a3, a2, b2, c2, d2, 3);
}
```

<script type="text/javascript" src="http://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-MML_HTMLorMML"></script>