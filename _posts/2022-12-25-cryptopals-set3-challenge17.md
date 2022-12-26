---
layout: post
title:  "Cryptopals Set 3, Challenge 17"
author: Anton Kueltz
tag: cryptopals
---

Welcome to set 3! We start this set with a stone cold _classic_ of an attack. What we have
to implement is a [padding oracle attack against CBC mode](https://cryptopals.com/sets/3/challenges/17).
This attack has famously been breaking TLS implementations for a long time, starting
with [Serge Vaudenay's attack](https://www.iacr.org/cryptodb/archive/2002/EUROCRYPT/2850/2850.pdf)
and including, among others, the [Lucky Thirteen](http://www.isg.rhul.ac.uk/tls/TLStiming.pdf) and
[POODLE](https://www.openssl.org/~bodo/ssl-poodle.pdf) attacks. This attack is great. In
this instance we'll have a pretty straightforward oracle, but the brilliance in this attack
is that if you don't have one of those you can combine this with e.g. a timing side channel
attack (measuring e.g. that padding failures return faster than valid decryptions) to
create your own oracle (this is _roughly_ what Lucky Thirteen did). Let's take a look at
how it works.

# Preliminaries

The first function we need to implement is one that generates our ciphertexts. We'll generate
a random key and IV for encryption and randomly chose a target message from a provided list of plaintexts.
We then encrypt the message and return the corresponding ciphertext and IV. The key will remain unknown to
us, of course, since we will be recovering the plaintext by other means.

```python
from base64 import b64decode
from os import urandom
from random import choice
from typing import Tuple

from challenge11 import aes_cbc_encrypt

from Crypto.Cipher import AES

key = urandom(AES.block_size)


def generate_ciphertext() -> Tuple[bytes, bytes]:
    iv = urandom(AES.block_size)
    message = choice([
        'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93',
    ])

    ciphertext = aes_cbc_encrypt(b64decode(message), key, iv)

    return ciphertext, iv
```

Next we need a function (the padding oracle) that takes a ciphertext, decrypts it,
and tells us if the padding on the decrypted bytes is valid. Luckily for us, this is
just composing functions we implemented already in previous challenges.

```python
from challenge10 import aes_cbc_decrypt
from challenge15 import is_valid_pkcs7_padding


def padding_oracle(ciphertext: bytes, iv: bytes) -> bool:
    plaintext = aes_cbc_decrypt(ciphertext, key, iv)
    return is_valid_pkcs7_padding(plaintext)
```

# The Padding Oracle Attack

Let's do a quick refresher of CBC mode. Recall that the decryption for block i, where P is
the plaintext and C is the ciphertext, is defined as

P<sub>i</sub> = C<sub>i-1</sub> XOR AES(C<sub>i</sub>)

We know the value of C, and we want to recover P, so we need to determine what the value
of AES(C<sub>i</sub>) is for each block. It turns out we can do this with the padding oracle. Suppose
we randomly set the last byte of C<sub>i-1</sub>. There is a 1 in 2<sup>8</sup> = 256 chance that this
causes the last byte of P<sub>i</sub> to be `\x01`. How would we know when this happens? Via the padding
oracle because this is valid PKCS#7 padding. We then can derive the the last byte of AES(C<sub>i</sub>)
by calculating `\x01` XOR the last byte of of C<sub>i-1</sub>. Once we have that byte we derive the last
byte of P<sub>i</sub> per the formula above.

The same principle then applies to all the remain bytes in the block. For the second to last byte we first set
the last byte of C<sub>i-1</sub> such that the last byte of P<sub>i</sub> is `\x02` and then we guess the
second to last byte in C<sub>i-1</sub> until we find a plaintext with valid padding. The plaintext must
then end in `\x02\x02`. Rinse and repeat byte by byte until we recover the whole block.

```python
from challenge02 import xor


def recover_block(target_block: bytes, previous_block: bytes) -> bytes:
    plaintext = b''

    # target byte index starting from the end (right) of the block
    for byte_index in range(AES.block_size):
        padding_byte = byte_index + 1

        # random bytes up to the target index
        modified_prefix = b'\x00' * (AES.block_size - byte_index - 1)
        
        # bytes after the target index, modified to decrypt to the pad byte
        pad_bytes = padding_byte.to_bytes(1, byteorder='little') * byte_index
        previous_block_suffix = previous_block[AES.block_size - byte_index:]
        modified_suffix = xor(xor(plaintext, pad_bytes), previous_block_suffix)

        for guess in range(0xff + 1):
            guess_byte = guess.to_bytes(1, byteorder='little')
            modified_previous_block = modified_prefix + guess_byte + modified_suffix

            if padding_oracle(target_block, modified_previous_block):
                pre_xor_decrypted_byte = padding_byte ^ guess
                plaintext_byte = pre_xor_decrypted_byte ^ previous_block[-(byte_index + 1)]
                plaintext = plaintext_byte.to_bytes(1, byteorder="little") + plaintext
                break
    
    return plaintext
```

This code is tricky enough to get right that it's worth commenting and also discussing a bit more. The
first question is - why use random bytes for all the bytes in C<sub>i-1</sub> up until the target index?
This is because the last plaintext block will have padding in it. This means that the last byte (which we start with)
`\x01` is a valid plaintext byte, but _so is the actual padding byte_. More concretely, if our decrypted
plaintext ends padded with `\x03\x03\x03` then either `\x01` or `\x03` is a valid last plaintext byte and
our oracle returns true in both instances. To make this much less likely to occur we set all bytes in
C<sub>i-1</sub> leading up to our target index to `\0x00` and rely on the randomness of AES to prevent any
other valid paddings from entering the plaintext before our target byte (note that this does not prevent
it entirely, but statistically speaking it's good enough).

The other tricky part is how `modified_suffix` gets set. These are the bytes in C<sub>i-1</sub> that are
after our target index and which we need to massage to ensure that the ending plaintext bytes are valid
padding. We work backwards here, starting with the requirement that the last n-1 bytes of P must be equal
to n (n-1 bytes because the nth padding byte is our target byte). Working from there we know that the
value of AES(C<sub>i</sub>) for the last n-1 bytes is the plaintext bytes we have recovered xored with the
original last bytes of the previous ciphertext block. We then set the previous ciphertext's n-1 last bytes
to AES(C<sub>i</sub>) xored with the padding bytes. Thus the bytes after the target byte in the plaintext
are all padding bytes. We can convince ourselves via the equation below (where block<sub>x</sub> is shorthand for
the bytes after the target byte in block x)

P<sub>i</sub> = C<sub>i-1</sub> XOR AES(C<sub>i</sub>) = (AES(C<sub>i</sub>) XOR padding) XOR AES(C<sub>i</sub>) = padding

Now we just need some control flow to apply our block recovery function to the whole ciphertext.

```python
def recover_message(ciphertext: bytes, iv: bytes) -> bool:
    plaintext = b''
    previous_block = iv

    for i in range(len(ciphertext) // AES.block_size):
        start = i * AES.block_size
        end = start + AES.block_size
        current_block = ciphertext[start:end]

        plaintext += recover_block(current_block, previous_block)
        previous_block = current_block
    
    # strip padding
    padding_byte = plaintext[-1].to_bytes(1, byteorder="little")
    return plaintext.rstrip(padding_byte)
```

Putting it all together we now have a functional padding oracle attack. Again, one of the cool things about
this attack is that you can have the `padding_oracle` function essentially be a black box and this attack
will work. It doesn't matter how you determine valid padding (explicit server feedback, timing analysis, etc),
as long as you have a reliable signal on whether or not the padding is valid this attack will work.

```python
from base64 import b64decode
from os import urandom
from random import choice
from typing import Tuple

from challenge02 import xor
from challenge10 import aes_cbc_decrypt
from challenge11 import aes_cbc_encrypt
from challenge15 import is_valid_pkcs7_padding

from Crypto.Cipher import AES

key = urandom(AES.block_size)


def generate_ciphertext() -> Tuple[bytes, bytes]:
    iv = urandom(AES.block_size)
    message = choice([
        'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93',
    ])
    print(b64decode(message))

    ciphertext = aes_cbc_encrypt(b64decode(message), key, iv)

    return ciphertext, iv


def padding_oracle(ciphertext: bytes, iv: bytes) -> bool:
    plaintext = aes_cbc_decrypt(ciphertext, key, iv)
    return is_valid_pkcs7_padding(plaintext)


def recover_block(target_block: bytes, previous_block: bytes) -> bytes:
    plaintext = b''

    # target byte index starting from the end (right) of the block
    for byte_index in range(AES.block_size):
        padding_byte = byte_index + 1

        # random bytes up to the target index
        modified_prefix = b'\x00' * (AES.block_size - byte_index - 1)
        
        # bytes after the target index, modified to decrypt to the pad byte
        pad_bytes = padding_byte.to_bytes(1, byteorder='little') * byte_index
        previous_block_suffix = previous_block[AES.block_size - byte_index:]
        modified_suffix = xor(xor(plaintext, pad_bytes), previous_block_suffix)

        for guess in range(0xff + 1):
            guess_byte = guess.to_bytes(1, byteorder='little')
            modified_previous_block = modified_prefix + guess_byte + modified_suffix

            if padding_oracle(target_block, modified_previous_block):
                pre_xor_decrypted_byte = padding_byte ^ guess
                plaintext_byte = pre_xor_decrypted_byte ^ previous_block[-(byte_index + 1)]
                plaintext = plaintext_byte.to_bytes(1, byteorder="little") + plaintext
                break
    
    return plaintext


def recover_message(ciphertext: bytes, iv: bytes) -> bool:
    plaintext = b''
    previous_block = iv

    for i in range(len(ciphertext) // AES.block_size):
        start = i * AES.block_size
        end = start + AES.block_size
        current_block = ciphertext[start:end]

        plaintext += recover_block(current_block, previous_block)
        previous_block = current_block
    
    # strip padding
    padding_byte = plaintext[-1].to_bytes(1, byteorder="little")
    return plaintext.rstrip(padding_byte)


def challenge17():
    ciphertext, iv = generate_ciphertext()
    print(recover_message(ciphertext, iv))
```
