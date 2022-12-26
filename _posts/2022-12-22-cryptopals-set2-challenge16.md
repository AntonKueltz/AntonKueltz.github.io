---
layout: post
title:  "Cryptopals Set 2, Challenge 16"
author: Anton Kueltz
tag: cryptopals
---

In the final challenge of the second set we ease up on poor ECB mode and
[pick on CBC mode instead](https://cryptopals.com/sets/2/challenges/16). While ECB mode
is commonly shunned in "serious" production systems, we see CBC mode quite a lot. In
fact, as recently as TLS 1.2 CBC mode was used to secure HTTPS traffic. If there is a
takeaway from this challenge it's that using the right cryptographic primitives often
isn't enough. You have to combine and apply them correctly too in order to have a safe
system. Even big, respected TLS implementations like openSSL have learned this the hard
way.

# Preliminaries

Anyway, let's flip some bits for fun and profit. Before we do that we have a couple
preliminaries we need to set up again to act as the canvas upon which we will paint our
attack. The first function we need to write is one which takes some bytes that we provide
and sets the `userdata` field of an object to that value. The data is then encrypted in
CBC mode under a random AES key.

```python
from os import urandom

from challenge11 import aes_cbc_encrypt

from Crypto.Cipher import AES

key = urandom(AES.block_size)
iv = urandom(AES.block_size)


def set_and_encrypt_data(user_data: bytes) -> bytes:
    sanitized = user_data.replace(b';', b'%3B').replace(b'=', b'%3D')
    comment1 = b'comment1=cooking%20MCs;userdata='
    comment2 = b';comment2=%20like%20a%20pound%20of%20bacon'

    user = comment1 + sanitized + comment2
    return aes_cbc_encrypt(user, key, iv)
```

We also sanitize the input so that injecting arbitrary fields via `user_data` is not possible.
This is relevant to the next function, which decrypts and checks if there is an `admin` field which 
is set to `true`. Sanitization of the input ensures that we can't simply inject `user_data` with
a substring of `;admin=true;`.

```python
from challenge10 import aes_cbc_decrypt


def is_admin(encrypted_data: bytes) -> bool:
    user = aes_cbc_decrypt(encrypted_data, key, iv)
    user_object = {}

    for field in user.split(b';'):
        field_name, value = field.split(b'=')
        user_object[field_name] = value
    
    return user_object.get(b'admin') == b'true'
```

At this point we can check that our sanitization is working correctly by trying to inject an admin role.

```python
In [1]: encrypted = set_and_encrypt_data('foo;admin=true')

In [2]: is_admin(encrypted)
Out[2]: False
```

# The Bitflipping Attack

Luckily for us the integrity of the ciphertext is not verified and we are free to modify it as we like before
sending it to the `is_admin` function. This is where the bitflipping comes into play. Recall that encryption in
CBC mode, applied to the input we have in this problem, looks something like this -

```
                |comment1=cooking|    |%20MCs;userdata=|    |<attacker data>|
                        |                     |                      |
                        V                     V                      V
|... IV bytes ...|---> XOR          +------> XOR          +-------> XOR
                        |           |         |           |          |
                        V           |         V           |          V
                       AES          |        AES          |         AES
                        |           |         |           |          |
                        V           |         V           |          V
                |   ciphertext   | -+ |   ciphertext   | -+ |   ciphertext   | ->...
```

Decryption is then as follows -

```
                |   ciphertext   | -+ |   ciphertext   | -+ |   ciphertext   |
                        |           |         |           |         |
                        V           |         V           |         V
                       AES          |        AES          |        AES
                        |           |         |           |         |
                        V           |         V           |         V 
|... IV bytes ...|---> XOR          +------> XOR          +------> XOR
                        |                     |                     |
                        V                     V                     V
                |comment1=cooking|    |%20MCs;userdata=|    |<attacker data>|
```

Let's use some terms to keeps things consistent and say that `P0` is the first plaintext
block and `C0` is the first ciphertext block (with `P1` and `C1` being the second block and
so on). We'll also say that `A` is the input block of the plaintext that we control and that
`T` is the target block that we want to have as part of the decrypted output. In the decryption
process we know that `P2 = A`, which means we also can determine the output of `AES(C2)`,
the AES decryption call, before the `XOR` is applied -

```
AES(C2) = C1 XOR A
```

We can't change the value of `AES(C2)`, but nothing is preventing us from swapping out `C1` for
some value that we control. We want to switch out `C1` for a new value, let's call it `C1'`,
such that `C1' XOR AES(C2) = T`. We derive it thus -

```
C1' = T XOR AES(C2) = T XOR C1 XOR A
```

Note that we control `A`, can choose `T`, and have knowledge of `C1` so we can craft
this `C1'` block for any `T` that we arbitrarily choose. There is one side effect - `P1` is now
going to be complete gibberish since we are passing it a modified ciphertext block. That means
that our `T` block will need to prepend `;` to whatever data we want to set in order to ensure
that the gibberish does not spill over to the data we want to inject.

```python
from challenge02 import xor


def replace_ciphertext_block(target: bytes, ctxt: bytes, user_data: bytes) -> bytes:
    target_ciphertext_block = ctxt[AES.block_size:2 * AES.block_size]  # C1

    decrypted_before_xor = xor(target_ciphertext_block, user_data)  # AES(C2)
    modified_ciphertext_block = xor(target, decrypted_before_xor)  # C1'
    
    start = ctxt[:AES.block_size]
    end = ctxt[2 * AES.block_size:]
    return start + modified_ciphertext_block + end
```

Visually this is what we have done in replacing the second ciphertext block -

```
                |       C0       | -+ | T XOR C1 XOR A | -+ |       C2       |
                        |           |         |           |         |
                        V           |         V           |         V
                       AES          |        AES          |        AES
                        |           |         |           |         | (= C1 XOR A)
                        V           |         V           |         V 
|... IV bytes ...|---> XOR          +------> XOR          +------> XOR
                        |                     |                     |
                        V                     V                     V
                |comment1=cooking|    |   <gibberish>  |    |       T        |
```

So here we now have a chosen ciphertext attack where we can control an entire block of the
plaintext without knowing the key. This again highlights the importance of ensuring ciphertext
integrity by e.g. computing a MAC over the ciphertext and verifying it before decrypting the
ciphertext. Putting it all together we have our solution for the last challenge in set 2.

```python
from os import urandom

from challenge02 import xor
from challenge10 import aes_cbc_decrypt
from challenge11 import aes_cbc_encrypt

from Crypto.Cipher import AES

key = urandom(AES.block_size)
iv = urandom(AES.block_size)


def set_and_encrypt_data(user_data: bytes) -> bytes:
    sanitized = user_data.replace(b';', b'%3B').replace(b'=', b'%3D')
    comment1 = b'comment1=cooking%20MCs;userdata='
    comment2 = b';comment2=%20like%20a%20pound%20of%20bacon'

    user = comment1 + sanitized + comment2
    return aes_cbc_encrypt(user, key, iv)


def is_admin(encrypted_data: bytes) -> bool:
    user = aes_cbc_decrypt(encrypted_data, key, iv)
    user_object = {}

    for field in user.split(b';'):
        field_name, value = field.split(b'=')
        user_object[field_name] = value
    
    return user_object.get(b'admin') == b'true'


def replace_ciphertext_block(target: bytes, ctxt: bytes, user_data: bytes) -> bytes:
    target_ciphertext_block = ctxt[AES.block_size:2 * AES.block_size]

    decrypted_before_xor = xor(target_ciphertext_block, user_data)  # AES(C2)
    modified_ciphertext_block = xor(target, decrypted_before_xor)   # C1'
    
    start = ctxt[:AES.block_size]
    end = ctxt[2 * AES.block_size:]
    return start + modified_ciphertext_block + end


def challenge16():
    user_data = b'A' * AES.block_size
    target = b'dataz;admin=true;'

    encrypted = set_and_encrypt_data(user_data)
    modified = replace_ciphertext_block(target, encrypted, user_data)
    
    assert is_admin(modified)
    print("Created object with admin=true")
```
