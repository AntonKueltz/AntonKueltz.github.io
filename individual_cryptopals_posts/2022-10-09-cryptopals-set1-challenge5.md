---
layout: post
title: "Implement Repeating-key XOR"
subtitle:  "Cryptopals Set 1, Challenge 5"
author: Anton Kueltz
tag: cryptopals
---

Keys longer than one byte! We're starting to slowly but surely move toward challenges
where we can't brute force the key space quickly. Here we are [tasked with implementing
a repeating key XOR](https://cryptopals.com/sets/1/challenges/5), meaning we repeat the
key to be the length of the plaintext and then xor the two together.
```
Burning `em
|||||||||||
ICEICEICEIC
```
We make this a little more efficient by noting that the corresponding key byte for a
plaintext byte at index `i` is the key byte at index `i % len(key)`. This is because the
key repeats every `len(key)` bytes.

```python
from binascii import hexlify


def repeating_key_xor(intxt: bytes, key: bytes) -> bytes:
    outtxt = []

    for i, c in enumerate(intxt):
        key_index = i % len(key)
        outtxt.append(c ^ key[key_index])

    return bytes(outtxt)


def challenge05() :
    plaintext = b'Burning \'em, if you ain\'t quick and nimble ' \
                b'I go crazy when I hear a cymbal'
    key = b'ICE'
    ctxt = repeating_key_xor(plaintext, key)
    print(hexlify(ctxt))
```