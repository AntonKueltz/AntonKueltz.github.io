---
layout: post
title: "Detect AES in ECB Mode"
subtitle:  "Cryptopals Set 1, Challenge 8"
author: Anton Kueltz
tag: cryptopals
---

In the final challenge of set 1 
[we need to identify which ciphertext has been encrypted using ECB mode](https://cryptopals.com/sets/1/challenges/8). Recall that ECB mode will always
produce the same ciphertext block for two equal plaintexts blocks, 
provided that they are encrypted under the same key. So an easy way to check
for ECB mode is to see if there are two equal blocks in a ciphertext. Note
that we do not have to perform any decryption operations for us to be able
to identify the ciphertext encrypted in ECB mode.

```python
from binascii import hexlify, unhexlify
from typing import Optional

from Crypto.Cipher import AES


def is_encrypted_in_ecb_mode(ctxt: bytes) -> bool:
    blocks = set()

    for block in range(len(ctxt) // AES.block_size):
        start = block * AES.block_size
        end = start + AES.block_size
        block = ctxt[start:end]

        if block in blocks:
            return True

        blocks.add(block)

    return False


def challenge08():
    with open('8.txt', 'rb') as f:
        ctxts = [unhexlify(txt) for txt in f.read().split(b'\n')]

    for ctxt in ctxts:
        if is_encrypted_in_ecb_mode(ctxt):
            print(hexlify(ctxt))
```

# Appendix

While it is theoretically possible for ciphertexts encrypted with other block
cipher modes to have equal blocks, the probability of this happening is
so infinitesimal that it's not worth considering for this problem. To give a
more concrete example, consider
[CBC mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)).
If we assume that AES is a pseudorandom function, and that the IV is randomly
sampled, then we can also state that each ciphertext block is a randomly
sampled value from the function image (all possible 128 bit numbers) that is
independent of the plaintext block. We can then apply the 
[birthday paradox](https://en.wikipedia.org/wiki/Birthday_problem)
to determine how likely a collision (two equal blocks) is in such a ciphertext.
Given that members of a group can have any of `n` possible values, and there are
`k` members in the group, the probability that no two members have the same
value assigned to them is
```
(1 / n)^k * (n * (n-1) * (n-2) * ... * (n-k+1))
```
In our case the range of possible values is all 128 bit numbers, so `n=2^128`
possible values. If we have a `k=1000000` block plaintext then the probability of
two equal ciphertext blocks would be
```python
In [1]: n = 2**128

In [2]: k = 1000000

In [3]: from functools import reduce

In [4]: reduce(lambda x, y: x * (y / n), range(n, n-k, -1), 1.0)
Out[4]: 1.0
```
Python can't properly represent values this close to 1 due to floating point
representation limitations so let's reduce the possible values to `n=2^64`, which 
is about `1.94 * 10^19` times smaller than `n=2^128`. In this case the 
probability of no two equal blocks is
```python
In [1]: n = 2**64

In [2]: k = 1000000

In [3]: from functools import reduce

In [4]: reduce(lambda x, y: x * (y / n), range(n, n-k, -1), 1.0)
Out[4]: 0.9999999728949818
```
This means the probability of there not being a collision in a ciphertext that
is a million blocks long, using a block cipher with a function image of size `2^64`,
is 99.99999%. Now imagine how many more nines the probability has when we expand
the function image size by a factor of `1.94 * 10^19`. Given how incomprehensibly
unlikely this scenario is we do not take it into consideration for our approach
to identifying ciphertexts encrypted in ECB mode.
