---
layout: post
title:  "Cryptopals Set 1, Challenge 1"
author: Anton Kueltz
tag: cryptopals
---

To start we are [tasked with decoding some hex data and encoding the
resulting bytes in base64](https://cryptopals.com/sets/1/challenges/1). 
Not much cryptography happening here, but some useful utilities since 
we'll be given raw byte data (keys, ciphertexts, etc) in encoded form
later on. Python has everything we need to encode and decode various 
representations of bytes so all we have to do is chain together a couple
calls from the standard library.

```python
from base64 import b64encode
from binascii import unhexlify


def hex_to_b64(hex_str: bytes) -> bytes:
    raw = unhexlify(hex_str)
    return b64encode(raw)


def challenge01():
    hex_data = b'49276d206b696c6c696e6720796f757220627261696e206c' \
               b'696b65206120706f69736f6e6f7573206d757368726f6f6d'
    b64_data = hex_to_b64(hex_data)
    print(b64_data)
```