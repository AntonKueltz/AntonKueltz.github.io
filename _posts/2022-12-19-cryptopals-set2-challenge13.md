---
layout: post
title: "ECB Cut-and-paste"
subtitle:  "Cryptopals Set 2, Challenge 13"
author: Anton Kueltz
tags: ["cryptopals", "practical-exploit"]
---

In this challenge we [pick on poor ECB mode yet again](https://cryptopals.com/sets/2/challenges/13).
We are again going to exploit the fact that ECB deterministically encrypts each block, meaning that
under the same key two equal plaintext blocks will encrypt to the same ciphertext blocks. This
is where the "cut and paste" from the challenge title comes into play. You can arbitrarily swap the
position of blocks within a ciphertext without turning the corresponding plaintext into gibberish.
ECB also does not do anything to ensure the integrity of a ciphertext, we'd need to use a MAC or an
[authenticated encryption mode](https://en.wikipedia.org/wiki/Authenticated_encryption) for that.
So with ECB mode we can swap ciphertext blocks and the corresponding plaintext will also have the
same blocks swapped.

# Preliminaries

Before we start exploiting this property of ECB mode we need some preliminary utility functions. The
first is to decode a string (which the challenge calls a cookie) that is formatted like URL query parameters.
This format (in rough terms good enough for this challenge, don't use this as a URL query param parsing
spec!) is a key value list, where keys and values are separated by `=` and key value pairs are separated
by `&`. So a string of `key1=value1&key2=value2` would decode to the following `dict` in python -

```python
{
    "key1": "value1",
    "key2": "value2"
}
```

While we could use something like the  [`urllib.parse` module](https://docs.python.org/3/library/urllib.parse.html)
for this, it's simple enough that we can implement our own that doesn't have all the bells and whistles of parsing
a complete URL -

```python
def decode_cookie(cookie: str) -> dict:
    decoded = {}

    for pair in cookie.split('&'):
        key, value = pair.split('=')
        decoded[key] = value
    
    return decoded
```

We also need to write a `profile_for` function which takes an email and generates an encoded account object for 
a user, with the role of `'user'` and a user id. We need to encode the account object in the complementary process
to the parsing function we just wrote and return the encoded object as a string. We also need to ensure that we
escape the characters `'&'` and `'='`, lest we allow random key value pairs to be injected into the object via
the user specified email.

```python
def profile_for(email: str) -> str:
    sanitized_email = email.replace('&', '%26').replace('=', '%3D')

    return f'email={sanitized_email}&uid=10&role=user'
```

We can then run a couple sanity checks to ensure that sanitization and parsing are working correctly -

```python
In [1]: profile_object = decode_cookie(profile_for('foo@bar.com&role=admin'))

In [2]: assert profile_object['role'] == 'user'

In [3]: assert not profile_object['role'] == 'admin'

In [4]: assert profile_object['email'] == 'foo@bar.com%26role%3Dadmin'
```

Note that even though we tried to inject an admin role via the email the provided value was encoded and
thus we did not end up with an object where the `'role'` key had value `'admin'`. This is important
because we will be exploiting ECB mode to get an admin account, so we should convince ourselves that this
isn't possible simply by injecting the role via the email field.

# Cutting and Pasting ECB Blocks

We're now asked to write two functions that rely on the same shared AES key. One to encrypt an encoded user
profile and another to decrypt the profile and decode it.

```python
from os import urandom

from challenge07 import aes_ecb_decrypt
from challenge11 import aes_ecb_encrypt

key = urandom(16)


def encrypt_encoded_profile(profile: str) -> bytes:
    # note that encode call here means str => bytes, not profile object => str
    profile_bytes = profile.encode()
    return aes_ecb_encrypt(profile_bytes, key)


def decrypt_and_decode_profile(ciphertext: bytes) -> dict:
    profile_bytes = aes_ecb_decrypt(ciphertext, key)
    # note that decode here means bytes => str, not str => profile object
    profile = profile_bytes.decode()
    return decode_cookie(profile)
```

Now we have all the pieces we need for a cut and paste attack. Recall that cutting and pasting ciphertext blocks
in ECB mode corresponds to the same operations on the plaintext. We can use this to create a plaintext where we
have an account with the admin role. Consider this string -

```
email=hax0r@bar.admin___________com&uid=10&role=user<padding>
|--- block 1 --||--- block 2 --||--- block 3 --||--- block 4 --|
```

Note that we cut block 2 and paste it over block 4 to get the following string -

```
email=hax0r@bar.com&uid=10&role=admin___________
|--- block 1 --||--- block 2 --||--- block 3 --|
```

Now we have a string that looks like it will decode to an object with the admin role! All that is left is to ensure
the `_` characters after `admin` are valid padding so that decryption doesn't fail. Luckily we have already
implemented a function to generate valid padding in [challenge 9](/2022/11/04/cryptopals-set2-challenge9.html).
Thus we implement our cut and paste attack -

```python
from Crypto.Cipher import AES

from challenge09 import pkcs7


def cut_and_paste_attack() -> dict:
    admin_block = pkcs7(b'admin')
    email = 'hax0r@bar.' + admin_block.decode() + 'com'

    encrypted_profile = encrypt_encoded_profile(profile_for(email))
    # break profile into chunks the size of the AES block size
    blocks = [
        encrypted_profile[i * AES.blocksize:(i + 1) * AES.blocksize]
        for i in range(len(encrypted_profile) // AES.blocksize)
    ]
    encrypted_admin_profile = blocks[0] + blocks[2] + blocks[1]

    return decrypt_and_decode_profile(encrypted_admin_profile)
```

Combining everything together we have our full attack, which validates that we did indeed generate an account with
the admin role (we also get some style points for managing to have the email value be something that is formatted
like a valid email).

```python
def challenge13():
    profile = cut_and_paste_attack()
    print(profile)
    assert profile['role'] == 'admin'
```

Note that if we run this the assertion fails! Why? Because we haven't accounted for the padding bytes at the end of the
message, which causes the profile object to look something like this -

```python
{
    'email': 'hax0r@bar.com',
    'uid': '10',
    'role': 'admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
}
```

We can take care of this by stripping the padding in our decrypt and decode function. This is what any production system
would also do, so no need to worry about this being "cheating". This is also one of the times where getting back an `int`
when indexing a `bytes` sequence is a little annoying. It would be nice for this to work like string indexing in this case
and not have to convert the `int` back to `bytes`. Then again, there are other cases where this is a nice property.

```python
def decrypt_and_decode_profile(ciphertext: bytes) -> dict:
    profile_bytes = aes_ecb_decrypt(ciphertext, key)
    padding_byte = profile_bytes[-1].to_bytes(1, byteorder='little')
    profile_bytes = profile_bytes.rstrip(padding_byte)
    # note that decode here means bytes => str, not str => profile object
    profile = profile_bytes.decode()
    return decode_cookie(profile)
```

The complete attack is below -

```python
from os import urandom

from Crypto.Cipher import AES

from challenge07 import aes_ecb_decrypt
from challenge09 import pkcs7
from challenge11 import aes_ecb_encrypt

key = urandom(16)


def decode_cookie(cookie: str) -> dict:
    decoded = {}

    for pair in cookie.split('&'):
        key, value = pair.split('=')
        decoded[key] = value
    
    return decoded


def profile_for(email: str) -> str:
    sanitized_email = email.replace('&', '%26').replace('=', '%3D')

    return f'email={sanitized_email}&uid=10&role=user'


def encrypt_encoded_profile(profile: str) -> bytes:
    # note that encode call here means str => bytes, not profile object => str
    profile_bytes = profile.encode()
    return aes_ecb_encrypt(profile_bytes, key)


def decrypt_and_decode_profile(ciphertext: bytes) -> dict:
    profile_bytes = aes_ecb_decrypt(ciphertext, key)
    padding_byte = profile_bytes[-1].to_bytes(1, byteorder='little')
    profile_bytes = profile_bytes.rstrip(padding_byte)
    # note that decode here means bytes => str, not str => profile object
    profile = profile_bytes.decode()
    return decode_cookie(profile)


def cut_and_paste_attack() -> dict:
    admin_block = pkcs7(b'admin')
    email = 'hax0r@bar.' + admin_block.decode() + 'com'

    encrypted_profile = encrypt_encoded_profile(profile_for(email))
    # break profile into chunks the size of the AES block size
    blocks = [
        encrypted_profile[i * AES.block_size:(i + 1) * AES.block_size]
        for i in range(len(encrypted_profile) // AES.block_size - 1)
    ]
    encrypted_admin_profile = blocks[0] + blocks[2] + blocks[1]

    return decrypt_and_decode_profile(encrypted_admin_profile)


def challenge13():
    profile = cut_and_paste_attack()
    assert profile['role'] == 'admin'
    print(profile)
```

# Appendix: Variable Data

One of the nice things about the profile object is that only the email is variable, so the attacker
controls all the variable data. Suppose that the uid was also variable -

```
email=hax0r@bar.admin___________com&uid=<unknown>&role=user<padding>
|--- block 1 --||--- block 2 --||--- block 3 ???????? block 4 --|
```

This makes things more difficult as the boundary between block 3 and block 4 is now unknown and we
can't be sure that `role=` is the end of the penultimate block. In this case some trial and error
may be necessary. If we make some assumptions about user ids, such as that they are assigned
incrementally, then we should still be able to find the length of the uid fairly quickly. We can
keep increasing the size of the string after `admin___________` (i.e. the attacker controlled part
of block 3) until the resulting ciphertext changes in size. At that point we know that the last
block is all padding -

```
email=hax0r@bar.admin___________<our prefix>&uid=<unknown>&role=user<padding>
|--- block 1 --||--- block 2 --||--- block 3 ??????????? block 4 --||--- block 5 --|
```

At that point some algebra gives us ther size of uid

```python
len_uid = AES.blocksize * 2 - len(our_prefix) - len('&uid=') - len('&role=user')
```

We can then craft a prefix such that `role=` is again the end of its block. That prefix needs to
have a length of

```python
prefix_len = AES.block_size - len('com&uid=') - len_uid - len('&role=')
```

In the case where `prefix_len` is negative (i.e. uid is large enough that it spills into the next block(s))
then we simply add `AES.block_size` to the `prefix_len` until it is positive.
