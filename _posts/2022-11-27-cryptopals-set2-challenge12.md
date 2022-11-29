---
layout: post
title:  "Cryptopals Set 2, Challenge 12"
author: Anton Kueltz
tag: cryptopals
---

This is were things start to move from the realm of training wheels to practical
attacks. In this challenge we are tasked with 
[breaking an ECB encrypted ciphertext](https://cryptopals.com/sets/2/challenges/12)
one byte at a time. This challenge is probably complex enough that rather than throwing
a whole solution onto the end, as in previous challenges, we're going to write out
functions step by step as we go.

# Preliminaries and Groundwork

The first component we need is an oracle that takes
a byte sequence of our choosing, appends a constant byte sequence to the end, and
encrypts those bytes under a constant key. Since we've got some state (the key and the
appended byte sequence) to manage we'll use a class to encapsulate this.

```python
from os import urandom

from challenge11 import aes_ecb_encrypt


class EncryptionOracle:
    def __init__(self, appended: bytes):
        self.key = urandom(16)  # 128 bit key for AES
        self.appended = appended
    
    def encrypt(self, data: bytes) -> bytes:
        return aes_ecb_encrypt(data + self.appended, self.key)
```

With this context in mind, the objective in this problem is to figure out a way to recover 
the contents of the appended string using only this oracle. That's pretty cool when you
think about it! Given an unknown constant key and unknown constant sequence of bytes, and
having only control over a chosen prefix, we can use an encryption oracle to decrypt the
unknown sequence of bytes without ever learning the key! This also does not bode well for
ECB mode (and things won't get any better for ECB in the coming challenges).

Next we need to determine what the block size of the cipher is. This is already known to
us, but the idea here is that a practical application of this attack might start with us
not knowing any details such as block size, encryption mode, etc. Determining the block
size can be achieved by passing incrementally larger data to the encryption oracle until
the output length of the oracle changes. In other words, we increment the size of the byte
sequence that the oracle encrypts by one byte until it crosses the boundary of a block.
The difference in output lengths is then the block size of the cipher.

```python
oracle = EncryptionOracle(b'')  # we'll make this the actual appended bytes later


def detect_block_size() -> int:
    data = b''
    initial_len = cur_len = len(oracle.encrypt(data))

    while cur_len == initial_len:
        data += b'A'
        cur_len = len(oracle.encrypt(data))

    return cur_len - initial_len
```

For step (2) we can reuse our `is_encrypted_in_ecb_mode` function from
[challenge 8](/2022/10/26/cryptopals-set1-challenge8.html). At step (3) we then use the block
size that we found earlier to craft an input such that the first byte of the appended byte
sequence is the last byte of the block we are encrypting. In other words we want to end up with
a block where only one byte is unknown to us. If we represent the unknown bytes in the appended
message with `?` and have a block size of `8` then our prefix would be e.g. `b'AAAAAAA'` and
we would be encrypting the following blocks -

```
AAAAAAA? ???????? ...
^^^^^^^
prefix
```

# Recovering A Single Byte

How is this prefix useful? It allows us to control the size of the search space. If an entire
block is unknown then there are `2^(8 * b)` possible values that the block could have (where `b`
is the length of the block in bytes). On the other hand, if the first `b-1` bytes are known then
the search space is `2^8`. We can easily brute force that search space. So, say we get back a
ciphertext where for the first input block we knew all the bytes except for one. We can then craft
`2^8` guesses that are the original prefix of `A` bytes plus a guess at the unknown byte.

```python
b'A...A\x00'
b'A...A\x01'
b'A...A\x02'
...
b'A...A\xff'
```

We can then pass each of these guesses to the oracle to build a dictionary mapping of output ciphertext
block to the last byte in that guess' prefix. This creates a lookup of ciphertext block to plaintext byte.

```python
from typing import Dict


def build_lookup_table(prefix: bytes) -> Dict[bytes, bytes]:
    block_size = len(prefix) + 1  # operate under assumption that only 1 byte is unknown
    lookup = {}

    for byte_as_int in range(0x100):
        byte = byte_as_int.to_bytes(1, byteorder="little")
        guess = prefix + byte

        ciphertext = oracle.encrypt(guess)
        first_block = ciphertext[:block_size]
        lookup[first_block] = byte
    
    return lookup
```

We now have all the pieces we need to decrypt byte by byte. We use the following steps -

1. Determine that the mode is ECB and that this attack is feasible.
1. Determine the block size so that we know how to craft our prefixes.
1. Craft a prefix such that one byte of an input block is unknown.
1. Create a map of ciphertext block to unknown byte for every possible value of the unknown byte.
1. Recover the unknown byte using the map.

```python

def recover_byte() -> bytes:
    block_size = detect_block_size()
    prefix = b'A' * (block_size - 1)

    ciphertext = oracle.encrypt(prefix)
    target_ciphertext_block = ciphertext[:block_size]

    lookup = build_lookup_table(prefix)
    return lookup[target_ciphertext_block]
```

At this point it's worth running a proof of concept to make sure that everything is working
as intended. We'll initialize `EncryptionOracle` with `b'secret'` as the unknown string. We
then expect that `recover_byte()` will return `b's'` when we run it.

```python
In [1]: from challenge12 import recover_byte

In [2]: recover_byte()
Out[2]: b's'
```

# Extending to Multiple Bytes and Blocks

With the meat of the problem out of the way the rest of this problem takes us a bit out
of the realm of purely cryptanalysis and into the realm of writing good control flow as well.
The remaining questions to answer are -

1. How do we break the next bytes in the first block?
2. How do we break the bytes in subsequent blocks?

The first question has a pretty straightforward answer - we incorporate the byte we just recovered
into the next lookup table. So if e.g. we just recovered `b's'` then our new prefix becomes `b'A..A'` with
one less `A`. Our lookup prefix then becomes the `A` bytes _plus_ the known bytes. In this way
we can recover the entire first block. The trick is that we always want to have exactly one unknown byte
in the block and that we want to keep incorporating the bytes we recover into our next lookup table.
Note that how we construct the lookup is adaptive and that we enclose things in a loop, but that the
core of the attack is not changed.

```
AAAAAAAAAAAAAAs?
^^^ input ^^^^
^^^^ known ^^^^
```

```python
def recover_block() -> bytes:
    known_bytes = b''
    block_size = detect_block_size()

    while len(known_bytes) != block_size:
        a_bytes = block_size - len(known_bytes) - 1
        prefix = b'A' * a_bytes

        ciphertext = oracle.encrypt(prefix)
        target_ciphertext_block = ciphertext[:block_size]

        lookup = build_lookup_table(prefix + known_bytes)
        known_bytes += lookup[target_ciphertext_block]

    return known_bytes
```

We can test this with a longer appended byte sequence to verify we can decode an entire block. In this
case we'll use the byte sequence `b'secret message, do not distribute'`.

```python
In [1]: from challenge12 import recover_block

In [2]: recover_block()
Out[2]: b'secret message, '
```

Now all that's left is to extend this to multiple blocks. This gets a little tricky in that the `A` byte
prefix is no longer a part of the lookup table prefix after the first block is recovered.
Instead it's the `block_size - 1` known bytes before the unknown byte that we use. There's also an edge case when
moving across block boundaries where we need to cycle the size of our prefix from 0 back to 15 in order
to get a single unknown byte in the next block e.g. -

```
|=== block1 ===| |=== block2 ===| |=== block3 ===|
AAAAAAAAAAAAAAAs ecret message, ? ????????????????
^^^^ input ^^^^
^^^^^^^^^^^^ known ^^^^^^^^^^^^^
```

So in the case above `b'ecret message, ` would be the lookup table prefix that we use.

```python
def recover_appended_message() -> bytes:
    known_bytes = b''
    current_block = 0

    block_size = detect_block_size()
    target_length = len(oracle.encrypt(b''))

    while len(known_bytes) != target_length:
        block_start = current_block * block_size
        block_end = block_start + block_size

        a_bytes = block_size - (len(known_bytes) % block_size) - 1
        prefix = b'A' * a_bytes

        ciphertext = oracle.encrypt(prefix)
        target_ciphertext_block = ciphertext[block_start:block_end]

        if current_block == 0:
            lookup_prefix = prefix + known_bytes
        else:
            lookup_prefix = known_bytes[-(block_size - 1):]

        lookup = build_lookup_table(lookup_prefix)
        known_bytes += lookup[target_ciphertext_block]

        if len(known_bytes) % block_size == 0:
            current_block += 1

    return known_bytes
```

If we run this we'll notice that we actually get an error!

```python
In [1]: from challenge12 import recover_appended_message

In [2]: recover_appended_message()
---------------------------------------------------------------------------
KeyError                                  Traceback (most recent call last)
Cell In [2], line 1
----> 1 recover_appended_message()

File challenge12.py, in recover_appended_message()
         lookup_prefix = known_bytes[-(block_size - 1):]
     lookup = build_lookup_table(lookup_prefix)
---> known_bytes += lookup[target_ciphertext_block]
     print(known_bytes)
     if len(known_bytes) % block_size == 0:

KeyError: b'<some byte sequence>'
```

Recall that we need to pad any input to AES to be a multiple of the block size and that we do
this with PKCS#7 padding. Assume that want to recover `b'secret'` but that all we know is that
we need to recover one block since that is the size of the ciphertext that the oracle gives back
when we do `target_length = len(oracle.encrypt(b''))`. Notice that the padding of what is
encrypted will actually change once we have recovered the six bytes of the message and try to recover
the padding.

```
#### Round 7 ####
AAAAAAAAAsecret\x01
^^input^^
^^^^ known ^^^^

==> known_bytes = b'secret\x01' after round 7

#### Round 8 ####
AAAAAAAAsecret\x02\x02
^^input^
^^^^ known ^^^????
```

We have a mismatch in this case. We recovered the `b'\x01'` padding byte in the seventh round, but then in
the eighth round that `b'\x01'` byte that we "know" is no longer valid since the padding is different and
our lookup fails as a result since we built a mapping based on a prefix that is not correct this round. So
we need to figure out a way to recover the unpadded message length. We can do this in a similar way that
we detected the block size. We pass the oracle input byte sequences that increase in size by one each
iteration. Once the ciphertext size changes we know that the size of the byte sequence is how many
padding bytes were initially in the padded plaintext.

```python
def detect_appended_bytes_length() -> int:
    data = b''
    initial_len = cur_len = len(oracle.encrypt(data))

    while cur_len == initial_len:
        data += b'A'
        cur_len = len(oracle.encrypt(data))
    
    padding_bytes = len(data)
    return initial_len - padding_bytes
```

We can then update our assignment of `target_length` to use this new, more accurate, method.

```diff
- target_length = len(oracle.encrypt(b''))
+ target_length = detect_appended_bytes_length()
```

```python
In [1]: from challenge12 import recover_appended_message

In [2]: recover_appended_message()
Out[2]: b'secret message, do not distribute'
```

# Optimizations

With a functional implementation under our belt we can now turn to optimizing a bit. We can't
do much better on the time complexity front since we're going to have to brute force each byte,
but we can improve space complexity. Note that for each round recovering a byte requires us
to build a map of all possible encryptions of the unknown byte. We don't actually need this map.
Instead of the map we can just check for the right ciphertext block as we are generating the
ciphertexts that are the keys of the map, making it unnecessary to maintain a map at all. This
reduces our space complexity quite a bit each round since the map is the only data structure we
maintain. In big O terms we have reduced the space needed from `O(2^8 * n) = O(n)` to `O(1)` 
(where `n` is the length of the byte sequence we are recovering and the constant factor accounts
for the size of the search space). In theory (aka big O terms) the time complexity is still the
same, but in practice it will be faster (unless the unknown byte is always `b'\xff'`) since we
can short circuit once we find the match.

```python
def recover_byte(prefix: bytes, target_block: bytes) -> bytes:
    block_size = len(prefix) + 1  # operate under assumption that only 1 byte is unknown

    for byte_as_int in range(0x100):
        byte = byte_as_int.to_bytes(1, byteorder="little")
        guess = prefix + byte

        ciphertext = oracle.encrypt(guess)
        first_block = ciphertext[:block_size]
        
        if first_block == target_block:
            return byte
    
    raise ValueError(
        f"Could not recover byte with prefix {prefix} and target block {target_block}"
    )
```

We then update `recover_appended_message` to use this new function to recover bytes.

```diff
- lookup = build_lookup_table(lookup_prefix)
- known_bytes += lookup[target_ciphertext_block]
+ known_bytes += recover_byte(lookup_prefix, target_ciphertext_block)
```

With that our attack is complete. The full implementation can be found below.

```python
from base64 import b64decode
from os import urandom

from challenge08 import is_encrypted_in_ecb_mode
from challenge11 import aes_ecb_encrypt

oracle = None


class EncryptionOracle:
    def __init__(self, appended: bytes):
        self.key = urandom(16)  # 128 bit key for AES
        self.appended = appended
    
    def encrypt(self, data: bytes) -> bytes:
        return aes_ecb_encrypt(data + self.appended, self.key)


def detect_block_size() -> int:
    data = b'A'
    initial_len = cur_len = len(oracle.encrypt(data))

    while cur_len == initial_len:
        data += b'A'
        cur_len = len(oracle.encrypt(data))

    return cur_len - initial_len


def detect_appended_bytes_length() -> int:
    data = b''
    initial_len = cur_len = len(oracle.encrypt(data))

    while cur_len == initial_len:
        data += b'A'
        cur_len = len(oracle.encrypt(data))
    
    padding_bytes = len(data)
    return initial_len - padding_bytes


def recover_byte(prefix: bytes, target_block: bytes) -> bytes:
    block_size = len(prefix) + 1  # operate under assumption that only 1 byte is unknown

    for byte_as_int in range(0x100):
        byte = byte_as_int.to_bytes(1, byteorder="little")
        guess = prefix + byte

        ciphertext = oracle.encrypt(guess)
        first_block = ciphertext[:block_size]
        
        if first_block == target_block:
            return byte
    
    raise ValueError(
        f"Could not recover byte with prefix {prefix} and target block {target_block}"
    )


def recover_appended_message() -> bytes:
    known_bytes = b''
    current_block = 0

    block_size = detect_block_size()
    target_length = detect_appended_bytes_length()

    while len(known_bytes) != target_length:
        block_start = current_block * block_size
        block_end = block_start + block_size

        a_bytes = block_size - (len(known_bytes) % block_size) - 1
        prefix = b'A' * a_bytes

        ciphertext = oracle.encrypt(prefix)
        target_ciphertext_block = ciphertext[block_start:block_end]

        if current_block == 0:
            lookup_prefix = prefix + known_bytes
        else:
            lookup_prefix = known_bytes[-(block_size - 1):]

        known_bytes += recover_byte(lookup_prefix, target_ciphertext_block)

        if len(known_bytes) % block_size == 0:
            current_block += 1

    return known_bytes


def challenge12():
    global oracle

    appended = b64decode(
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
        "YnkK"
    )
    oracle = EncryptionOracle(appended)

    assert is_encrypted_in_ecb_mode(oracle.encrypt(b'A' * 100))
    print(recover_appended_message())
```