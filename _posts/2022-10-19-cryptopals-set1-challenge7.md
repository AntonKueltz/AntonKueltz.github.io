---
layout: post
title:  "Cryptopals Set 1, Challenge 7"
---

In [this challenge](https://cryptopals.com/sets/1/challenges/7)
we get our first usage of modern cryptography, namely
the AES cipher. Python doesn't implement AES as part of the standard 
library so we can either implement it ourselves or use a third party
library. Implementing it ourselves would be useful if we're attacking
the internals of the cipher, such as doing cryptanalysis of the S-boxes,
but for these challenges we'll attack constructions that are one or more
"layers" higher than AES. That is to say, we'll attack vulnerable
protocols that build on AES, but where AES is not part of the attack
vector.

That being said, we'll be using
[`pycryptodome`](https://www.pycryptodome.org/) for most of our 
primitives that we don't implement ourselves. Why? Mainly because when I 
first solved these challenges years ago I used `pycrypto` and
`pycryptodome` has a compatible API and is still actively maintained.
The `cryptography` library is also probably just fine for this, although
I find primitives being under the `hazmat` category in their package
layout a bit obnoxious.

The only other thing to note here is that the block cipher mode we're
using is electronic codebook (ECB), which is somewhat famous for
[poorly encrypting images of penguins](https://words.filippo.io/the-ecb-penguin/).
This mode is quite simple, you take a block (128 bits in AES) of
plaintext, feed it into AES, get the ciphertext and rinse and repeat
until you're out of plaintext blocks. The final ciphertext is just
the concatenation of the ciphertext blocks. Wikipedia also has a nice
[diagram](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB)
describing this mode if you're a visual learner.

```python
from base64 import b64decode

from Crypto.Cipher import AES


def aes_ecb_decrypt(ctxt: bytes, key: bytes) -> bytes:
    ptxt = b''
    cipher = AES.new(key, AES.MODE_ECB)

    for block in range(len(ctxt) // AES.block_size):
        start = block * AES.block_size
        end = start + AES.block_size
        ptxt += cipher.decrypt(ctxt[start:end])

    return ptxt


def challenge07():
    key = b'YELLOW SUBMARINE'

    with open('Data/7.txt', 'rb') as f:
        data = b64decode(f.read().replace(b'\n', b''))
        print(aes_ecb_decrypt(data, key))
```