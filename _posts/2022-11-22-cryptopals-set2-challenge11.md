---
layout: post
title:  "Cryptopals Set 2, Challenge 11"
---

Having now got ECB mode and CBC mode under our belt, we are
[tasked with distinguishing ciphertexts encrypted in ECB and CBC mode](https://cryptopals.com/sets/2/challenges/11).
This is somewhat reminiscent of the [IND-CPA game](https://en.wikipedia.org/wiki/Ciphertext_indistinguishability#Indistinguishability_under_chosen-plaintext_attack_(IND-CPA))
that is sometimes used to prove the security of an encryption scheme against
a chosen plaintext attack. The gist of the black box whose output we must distinguish is -

1. It takes an arbitrary sequence of bytes from us to encrypt.
1. It generates a random AES key to use for the encryption.
1. It prepends and appends some random bytes to the data we gave it.
1. It flips a fair coin to decide whether to encrypt in ECB or CBC mode.
1. It encrypts the data and returns it to us.

Luckily we already have pretty much all of the pieces we need to do this. In
[challenge 8](/2022/10/26/cryptopals-set1-challenge8.html) we already wrote a method
to detect ECB mode that relied on there being two identical blocks in the ciphertext.
In order to identify the encryption mode that the black box used we just have to make
sure that two of the plaintext blocks it encrypts are the same. This is somewhat
complicated by random data being prepended and appended to the plaintext. To address
this we can craft a plaintext of one repeating character that is a sufficient length
that two of the plaintext blocks in the middle will be equal, regardless of the data
that is prepended and appended. We then run the ECB mode detector on the resulting
ciphertext. If it detects ECB mode then we know the black box used ECB mode, otherwise
we can be confident that the black box used CBC mode.

The only other thing to note here is that we also need to implement encryption for
ECB and CBC mode. We already implemented decryption for ECB and CBC mode in challenges
[7](/2022/10/19/cryptopals-set1-challenge7.html) and [10](/2022/11/06/cryptopals-set2-challenge10.html)
respectively so these functions should look pretty familiar.

```python
from os import urandom
from random import randint

from challenge02 import xor
from challenge08 import is_encrypted_in_ecb_mode
from challenge09 import pkcs7

from Crypto.Cipher import AES


def aes_ecb_encrypt(ptxt: bytes, key: bytes) -> bytes:
    ctxt = b''
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pkcs7(ptxt)

    for block in range(len(padded) // AES.block_size):
        start = block * AES.block_size
        end = start + AES.block_size
        ctxt += cipher.encrypt(padded[start:end])

    return ctxt


def aes_cbc_encrypt(ptxt: bytes, key: bytes, iv: bytes) -> bytes:
    ctxt = b''
    cipher = AES.new(key, AES.MODE_ECB)
    prev_block = iv
    padded = pkcs7(ptxt)

    for block in range(len(padded) // AES.block_size):
        start = block * AES.block_size
        end = start + AES.block_size
        cur_block = padded[start:end]

        tmp = xor(prev_block, cur_block)
        ctxtblock = cipher.encrypt(tmp)
        ctxt += ctxtblock

        prev_block = ctxtblock

    return ctxt


def encryption_oracle(data: bytes) -> bytes:
    key = urandom(16)
    randomized_data = urandom(randint(5, 10)) + data + urandom(randint(5, 10))

    if randint(0, 1):
        print('Encrypting in ECB mode...')
        return aes_ecb_encrypt(data, key)
    else:
        print('Encrypting in CBC mode...')
        iv = urandom(16)
        return aes_cbc_encrypt(data, key, iv)


def challenge11():
    ctxt = encryption_oracle(b'\x00' * 100)

    if is_encrypted_in_ecb_mode(ctxt):
        print('Detected ECB Mode')
    else:
        print('Detected CBC Mode')
```