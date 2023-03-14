---
layout: post
title: "Implement CBC Mode"
subtitle:  "Cryptopals Set 2, Challenge 10"
author: Anton Kueltz
tag: cryptopals
---

In this challenge we are tasked with [implementing CBC mode decryption](https://cryptopals.com/sets/2/challenges/10).
CBC mode is another block cipher mode for encrypting plaintexts of an arbitrary length.
If you read the appendix to the [challenge 8 post](https://www.antonkueltz.com/2022/10/26/cryptopals-set1-challenge8.html)
CBC mode might already sound familiar. It helps us avoid some of the issues that the deterministic
nature of ECB mode brings with it. The idea is to randomize the input to the cipher by first
XOR-ing the plaintext block with the previous ciphertext block. If the cipher can be modeled
as a pseudorandom function then each input to the cipher is pseudorandom since the input is the
XOR of a plaintext block and the output of a pseudorandom function.

For the more visually inclined, [Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC))
has a nice diagram of this process.
 
 ![CBC Mode Encryption](https://upload.wikimedia.org/wikipedia/commons/d/d3/Cbc_encryption.png)
 
 The decryption process is the reverse of this with the main "gotcha"
 being that we first apply the block cipher to the ciphertext block and then XOR the previous
 ciphertext block to obtain the plaintext block.

This addresses the ECB problem of equivalent plaintext blocks producing the same ciphertext blocks. 
The only other consideration is that the first plaintext block does not have a previous 
ciphertext block to XOR against. We solve this by passing an initialization vector (IV) as a
parameter to the encryption and decryption functions. This IV is randomly sampled and is what 
the first plaintext block is XOR-ed against. One last thing to note: when we say randomly sampled
we are referring to the output of a [CSPRNG](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator).
That is to say, a random number generator specifically for cryptographic applications. In the case
of this challenge the IV is hardcoded to a known constant. In real applications this would cause
issues (we would instead want to use e.g. `secrets.randbits` to generate the IV).

```python
from base64 import b64decode

from challenge02 import xor

from Crypto.Cipher import AES


def aes_cbc_decrypt(ctxt: bytes, key: bytes, iv: bytes) -> bytes:
    ptxt = b''
    cipher = AES.new(key, AES.MODE_ECB)
    prev_block = iv

    for block in range(len(ctxt) // AES.block_size):
        start = block * AES.block_size
        end = start + AES.block_size
        cur_block = ctxt[start:end]

        tmp = cipher.decrypt(cur_block)
        ptxt += xor(prev_block, tmp)

        prev_block = cur_block

    return ptxt


def challenge10():
    key = b'YELLOW SUBMARINE'
    iv = b'\x00' * AES.block_size

    with open('10.txt', 'rb') as f:
        data = b64decode(f.read().replace(b'\n', b''))
        print(aes_cbc_decrypt(data, key, iv))
```
