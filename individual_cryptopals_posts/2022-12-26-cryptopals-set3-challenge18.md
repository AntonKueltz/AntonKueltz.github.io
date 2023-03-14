---
layout: post
title:  "Implement CTR, the Stream Cipher Mode"
subtitle: "Cryptopals Set 3, Challenge 18"
author: Anton Kueltz
tag: cryptopals
---

In this challenge we [implement CTR mode, another block cipher mode](https://cryptopals.com/sets/3/challenges/18).
CTR (counter) is referred to as a stream cipher mode because it creates a keystream of
pseudorandom bytes and then XORs the input bytes against the keystream. In this mode the
block cipher is used to generate the keystream rather than directly encrypting the input
bytes. This is similar to how a one time pad (OTP) works, but with the distinction that a
OTP would be a keystream of truly random bytes and thus
[information theoretically secure](https://en.wikipedia.org/wiki/Information-theoretic_security).

The way we generate the keystream is that we get a nonce (number used once) as a parameter
and convert it into a 64 bit little endian byte sequence. We then append another 64 bit little
endian byte sequence to the nonce bytes that represents the index of the current block being
processed (starting with index 0). This index is the counter from which CTR mode gets its name.
We then have a 128 byte sequence, which is conveniently the block size that AES operates on. 
Python makes it nice and easy for us to encode our integers into the desired format. The
[`int.to_bytes`](https://docs.python.org/3/library/stdtypes.html#int.to_bytes)
method conveniently allows us to specify the byte size and byte order for the output. Thus
we can pass in `8` bytes (= 64 bits) and `byteorder='little'` to achieve the desired encoding.

```python
from base64 import b64decode
from math import ceil

from challenge02 import xor

from Crypto.Cipher import AES


def aes_ctr(in_bytes: bytes, key: bytes, nonce: int) -> bytes:
    out_bytes = b''
    nonce_bytes = nonce.to_bytes(8, byteorder='little')
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = ceil(len(in_bytes) / AES.block_size)

    for block in range(blocks):
        start = block * AES.block_size
        end = start + AES.block_size
        cur_block = in_bytes[start:end]

        nonce_and_count = nonce_bytes + block.to_bytes(8, byteorder='little')
        keystream = cipher.encrypt(nonce_and_count)

        out_bytes += xor(cur_block, keystream)
    
    return out_bytes


def challenge18():
    key = b'YELLOW SUBMARINE'
    encrypted = b64decode(
        b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/"
        b"2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    )

    print(aes_ctr(encrypted, key, 0))
```

# Appendix

Note that there is no distinction between encryption and decrytion in this mode, as pointed out in
the challenge description. As long as the key and nonce are the same the keystream that is generated
will be the same (this also introduces some attack vectors that we will exploit later). We can
convince ourselves that this works correctly as follows

```
Encrypt(x) = Decrypt(x) = x XOR keystream
Decrypt(Encrypt(x)) = (x XOR keystream) XOR keystream = x
```
