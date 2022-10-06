---
layout: post
title:  "Cryptopals Set 1, Challenge 2"
---

In this second challenge we are [tasked with computing the XOR of two
byte sequences](https://cryptopals.com/sets/1/challenges/2). First we
need to decode the hex encoded bytes, which we learned how to do in
the first challenge. Then we can operate on raw bytes and implement the 
XOR. The XOR operator is implemented via `^` in python. We can utilize 
the fact that the elements returned when iterating over a byte sequence 
in python can be interpreted as the integer  representation of that byte 
(e.g. `b'\xff'` => `255`). `^` operates on  integers so we grab elements 
pairwise from the two byte sequences we wish to XOR, apply `^` to the 
pairs, and then recombine the results into a byte sequence. `zip` 
(getting elements from two sequences pairwise) and list comprehensions 
(combining our results back into a sequence) make this easy to 
concisely implement.

```python
from binascii import hexlify, unhexlify


def xor(buf1: bytes, buf2: bytes) -> bytes:
    return bytes([b1 ^ b2 for (b1, b2) in zip(buf1, buf2)])


def challenge02():
    left = unhexlify(b'1c0111001f010100061a024b53535009181c')
    right = unhexlify(b'686974207468652062756c6c277320657965')
    xored = xor(left, right)
    print(hexlify(xored))
```