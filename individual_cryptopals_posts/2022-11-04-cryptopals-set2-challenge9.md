---
layout: post
title: "Implement PKCS#7 Padding"
subtitle:  "Cryptopals Set 2, Challenge 9"
author: Anton Kueltz
tag: cryptopals
---

In this challenge we have to [implement PKCS#7 padding](https://cryptopals.com/sets/2/challenges/9).
This is a fairly straightforward padding strategy. Given some sequence of bytes
and a block size we need to add padding bytes to the end of our sequence so that
the length of the sequence is a multiple of the block size. The padding bytes are
simply the byte representation of the number of bytes to pad. So if we need to add
six padding bytes then the padding would be `b\x06\x06\x06\x06\x06\x06` i.e. six bytes
that are the byte representation of six. Python has the `int.to_bytes` function which 
makes it easy to convert integers to bytes. The only edge case to consider is if the
sequence length is already a multiple of the block size. In that case we append
a full block of padding to the end of the byte sequence.

We can also verify the provided test vector in a python shell as an initial sanity check -

```python
In [1]: pkcs7(b"YELLOW SUBMARINE", 20)
Out[1]: b'YELLOW SUBMARINE\x04\x04\x04\x04'
```

```python
from Crypto.Cipher import AES


def pkcs7(data: bytes, block_size: int = AES.block_size) -> bytes:
    bytes_to_pad = block_size - (len(data) % block_size)
    padding_byte = int.to_bytes(bytes_to_pad, 1, byteorder='little')
    padding = padding_byte * bytes_to_pad
    return data + padding


def challenge09():
    print(pkcs7(b"YELLOW SUBMARINE", 20))
```