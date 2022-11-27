---
layout: post
title:  "Cryptopals Set 1, Challenge 6"
author: Anton Kueltz
tag: cryptopals
---

This challenges greets us with "It is officially on, now.". Indeed, in this 
challenge we are tasked with [breaking a ciphertext that has been encrypted
with the repeating key XOR](https://cryptopals.com/sets/1/challenges/6) 
from challenge 5. The key length is unknown so we
will first need to determine that. Once we have done that we will reduce the
problem to multiple single byte key ciphers (which we already know how to
break). More on that later, first let's talk about figuring out the key
size.

The first utility function we need to implement is `hamming_distance`, which
tells us how many bits differ between two byte sequences. The way we do this
is to take the XOR (pairwise, by byte) of the two sequences. The result of
the XOR will have a 1 bit at indices where the sequences differ and 0 bit
where they are the same. We can then use the newly introduced 
`int.bit_count` from python3.10 to count the number of 1 bits in the XOR 
result, which is the Hamming distance of the two sequences. We then verify 
that the test vector we are given in the problem produces the expected
output -

```python
In [1]: from challenge06 import hamming_distance

In [2]: hamming_distance(b'this is a test', b'wokka wokka!!!')
Out[2]: 37
```

Next we need to figure out how long the key actually is. The problem
statement tells us that to do this we can break the ciphertext into
blocks that are the size of a candidate key. We then find the Hamming
distance between those blocks and normalize it. Low values in this score
correlate to better candidates for key sizes. One thing the problem doesn't
get into is why this is. Consider we have a key that is three bytes long, 
let's say `b"KEY"`. Suppose we have a plaintext of `b"HIDDENSECRET"`. Then
our ciphertext is as follows -

```python
b"KEY" ^ b"HID" + b"KEY" ^ b"DEN" + b"KEY" ^ b"SEC" + b"KEY" ^ b"RET"
```

Note that when we compute the Hamming distance of the blocks against one
another the keys cancel out.

```python
b"KEY" ^ b"HID" ^ b"KEY" ^ b"DEN" = b"HID" ^ b"DEN"
```

This follows from some basic properties of XOR, namely -
* a ^ a = 0
* a ^ 0 = a

So when we pick the right key size our Hamming distance calculation is doing
the distance between the plaintext blocks. If we have a plaintext that is in
English (and make some sane assumptions about character encoding) then our
Hamming distance should be low, because most characters in English have very
similar bit representations, so their XOR is mostly 0 bits. Note that if we
pick the wrong key size this does not apply as the key bytes will not cancel
one another out. With wrong key sizes we expect a much more random
distribution of bytes being XORed in the Hamming distance calculation.

Once we have the top candidates for key sizes we apply the same principles
that we used to break single byte keys. We reduce each key byte of the
candidate key size into its own single byte cipher to be solved. We do this
by taking all the ciphertext bytes that would be encrypted under that key
byte, concatenate them, and create a new ciphertext that we already have
techniques for breaking. Once we have a candidate for each key byte we
produce the corresponding plaintext and score it. The highest score, as
always, will be our best candidate for the plaintext.

```python
from base64 import b64decode
from itertools import combinations
from typing import List

from challenge03 import score, find_single_byte_key
from challenge05 import repeating_key_xor


def hamming_distance(buf1: bytes, buf2: bytes) -> int:
    distance = 0

    for c1, c2 in zip(buf1, buf2):
        diff = c1 ^ c2
        distance += diff.bit_count()

    return distance


def _best_key_lengths(data: bytes) -> List[int]:
    dist_and_ksize = []

    for ksize in range(2, 41):
        blocks = []
        for block_start in range(0, ksize * 4, ksize):
            block_end = block_start + ksize
            blocks.append(data[block_start:block_end])

        distance = 0
        for block1, block2 in combinations(blocks, 2):
            distance += hamming_distance(block1, block2)

        dist_and_ksize.append((distance / ksize, ksize))

    dist_and_ksize.sort()
    return [ksize for (_, ksize) in dist_and_ksize[:3]]


def break_repeating_key(data: bytes) -> bytes:
    keylens = _best_key_lengths(data)
    best_score, ptxt = 0, b''

    for keylen in keylens:
        key = []
        blocks = [[] for _ in range(keylen)]

        for i, c in enumerate(data):
            blocks[i % keylen].append(c)
        blocks = map(bytes, blocks)

        for block in blocks:
            key.append(find_single_byte_key(block))
        key = bytes(key)

        txt = repeating_key_xor(data, key)
        cur_score = score(txt)

        if cur_score > best_score:
            best_score = cur_score
            ptxt = txt

    return ptxt


def challenge06():
    with open('6.txt', 'rb') as f:
        data = b64decode(f.read().replace(b'\n', b''))
        print(break_repeating_key(data))
```