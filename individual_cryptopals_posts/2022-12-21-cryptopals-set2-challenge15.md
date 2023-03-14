---
layout: post
title: "PKCS#7 Padding Validation"
subtitle:  "Cryptopals Set 2, Challenge 15"
author: Anton Kueltz
tag: cryptopals
---

We get a nice break in this challenge from the more code (and brain) intensive challenges
that we've had since challenge 12. Here the task is simple.
[Implement PKCS#7 padding validation](https://cryptopals.com/sets/2/challenges/15). We've
already implemented the padding itself in [challenge 9](/2022/11/04/cryptopals-set2-challenge9.html),
so we can reference that challenge for the details of the padding scheme.

There isn't much more to add here, the challenge recommends throwing an exception, but we'll
use a `bool` return type here. The effect is the same, but the interface feels a little cleaner.

```python
from Crypto.Cipher import AES


def is_valid_pkcs7_padding(data: bytes, block_size: int = AES.block_size) -> bool:
    pad_byte = data[-1]

    if pad_byte > block_size or pad_byte <= 0:
        return False

    return all([  # all padding bytes must match the expected value
        data_byte == pad_byte  # check that the padding byte has the expected value
        for data_byte in data[-pad_byte:]  # iterate over each padding byte
    ])


def challenge15():
    assert is_valid_pkcs7_padding(b'ICE ICE BABY\x04\x04\x04\x04')
    assert not is_valid_pkcs7_padding(b'ICE ICE BABY\x05\x05\x05\x05')
    assert not is_valid_pkcs7_padding(b'ICE ICE BABY\x01\x02\x03\x04')
    print('All provided test vectors passed')
```
