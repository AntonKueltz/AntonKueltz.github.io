---
layout: post
title:  "Cryptopals Set 2, Challenge 14"
author: Anton Kueltz
tag: cryptopals
---

This challenge modifies challenge 12, so check out [that post](/2022/11/27/cryptopals-set2-challenge12.html)
first as a preliminary. The difference is that
[in this challenge we prepend a random prefix to our input before encrypting](https://cryptopals.com/sets/2/challenges/14)
via the oracle. Recall that in challenge 12 the oracle appended the target bytes to our input.
In this challenge the oracle sandwiches our input between random bytes and the target bytes.

This means we'll need to modify our oracle class a bit. It's important to note that the random
prefix bytes are constant across oracle calls. We generate them once and then append them to every
input that the encyption oracle is queried on.

```python
from os import urandom
from random import randint

from challenge11 import aes_ecb_encrypt


class EncryptionOracle:
    def __init__(self, appended: bytes):
        self.key = urandom(16)  # 128 bit key for AES
        self.appended = appended
        prefix_bytes = randint(1, 100)
        self.prefix = urandom(prefix_bytes)
    
    def encrypt(self, data: bytes) -> bytes:
        return aes_ecb_encrypt(self.prefix + data + self.appended, self.key)
```

So why is this harder? It's more challenging because we don't know exactly where the block boundary
is right away, which means we'll have a harder time figuring out the length of the data that we want
to input in order to ensure only one unknown byte is in our block. There's also an additional
complication that we need to make sure that none of the prefix bytes get into our target block. If they
do then we'll be unable to properly create our lookup table since we'll have unknown random bytes
in the start of our input that will potentially vastly increase the search space.

So first let's find a way to identify block boundary between our input and the target data. Our
strategy is to start with input data of one byte less than 3 blocks worth of the same byte. This guarantees 
that we have two exactly equal ciphertext blocks. We then reduce the size of the input by one byte until
we no longer have two equal ciphertext blocks. When this happens we know that the difference between
plaintexts must look as follows (we use the `'A'` character as the repeating byte we inject in this example)

```
Previous Round:

<unknown prefix>A..AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<target>...<padding>
|--- block 1..n-2 ||-- block n-1 -||--- block n --||-- block n+1 ..._-|


Current Round

<unknown prefix>A..AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<target>...<padding>
|--- block 1..n-2 ||-- block n-1 -||--- block n --||-- block n+1 ...-|
```

So we know where block `n` is based on the previous round, namely it's the second block of the two matching
blocks in the previous round. Block `n-1` is then the target block that we use as a starting point for our
byte at a time decryption (we can forego the entire block of duplicate bytes in the attack as this was only 
useful for our ECB detection trick that allows us to find the block boundary). So we'll want to return both
`n-1`, the target block index, and also the number of bytes that we should use to extend the random prefix to
the next block boundary. Note that in the example below we use `0x00` rather than `'A'` as the target message
is much less likely to start with a zero byte and throw off our offset length.

```python
from typing import Tuple

from challenge08 import is_encrypted_in_ecb_mode

oracle = EncryptionOracle(b'target')


def get_pad_length_and_start_block(block_size: int) -> Tuple[int, int]:
    repeating_bytes = (3 * block_size - 1) * b'\x00'
    ciphertext = oracle.encrypt(repeating_bytes)
    assert is_encrypted_in_ecb_mode(ciphertext)

    target_block_index = -1
    for i in range(len(ciphertext) // block_size - 1):
        block_start = i * block_size
        block_end = next_block_start = block_start + block_size
        next_block_end = next_block_start + block_size

        block = ciphertext[block_start:block_end]
        next_block = ciphertext[next_block_start:next_block_end]

        if block == next_block:
            target_block_index = i
            break

    while is_encrypted_in_ecb_mode(ciphertext):
        repeating_bytes = repeating_bytes[:-1]
        ciphertext = oracle.encrypt(repeating_bytes)
    
    pad_length = len(repeating_bytes) - (block_size * 2 - 1)
 
    return pad_length, target_block_index
```

This is tricky enough that it's probably worth writing a small test driver to verify that
these values are what we expect. We run a couple rounds of the function against random
prefixes and check that (1) the pad length plus the prefix length is  a multiple
of the block size and (2) that we identify the correct block (the next full block after the
prefix) as the target block.

```python
def test_get_pad_length_and_start_block():
    global oracle
    block_size = 16

    for _ in range(100):
        oracle = EncryptionOracle(b'target')
        prefix_len = len(oracle.prefix)

        pad_length, block_index = get_pad_length_and_start_block(block_size)

        assert (prefix_len + pad_length) % block_size == 0
        assert (prefix_len + pad_length) // block_size == block_index

test_get_pad_length_and_start_block()
```

Once we've convinced ourselves that this is working we've completed the brunt of the challenge. All
that's left is to integrate these new constraints into our challenge 12 solution. We'll do this by
discussing the diffs between the challenge 12 functions and the challenge 14 functions (I'm sorry if
this gives anyone flashbacks to reviewing merge requests at work). Functions that did not change are
omitted.

```diff
def recover_appended_message() -> bytes:
    known_bytes = b''
-   current_block = 0

    block_size = detect_block_size()
-   target_length = detect_appended_bytes_length()
+   pad_length, start_block = get_pad_length_and_start_block(block_size)
+   random_prefix_length = start_block * block_size - pad_length
+   target_length = detect_appended_bytes_length(random_prefix_length)
 
+   current_block = start_block
+   constant_pad_bytes = b'A' * pad_length

    while len(known_bytes) != target_length:
        block_start = current_block * block_size
        block_end = block_start + block_size

        a_bytes = block_size - (len(known_bytes) % block_size) - 1
-       prefix = b'A' * a_bytes
+       prefix = constant_pad_bytes + (b'A' * a_bytes)

        ciphertext = oracle.encrypt(prefix)
        target_ciphertext_block = ciphertext[block_start:block_end]
 
-       if current_block == start_block:
+       if current_block == 0:
            lookup_prefix = prefix + known_bytes
        else:
-           lookup_prefix = known_bytes[-(block_size - 1):]
+           lookup_prefix = constant_pad_bytes + known_bytes[-(block_size - 1):]
 
-       known_bytes += recover_byte(lookup_prefix, target_ciphertext_block)
+       known_bytes += recover_byte(
+           lookup_prefix, target_ciphertext_block, start_block, block_size
+       )

        if len(known_bytes) % block_size == 0:
            current_block += 1

    return known_bytes
```

This is the core of the algorithm and also has the most changes to absorb. We start
by calculating the starting block and the number of bytes needed to pad the random
prefix to a multiple of the block size. We then also derive the length of the random
prefix. We update `current_block` accordingly, having the algorithm start on the first
block after the random prefix. We also calculate `constant_pad_bytes` which are used
to ensure that we always pad out the prefix to the end of a full block. You can see
that these bytes are prepended throughout the algorithm. The remaining changes are to
existing method calls that now need additional parameters. Let's look at one of those,
`recover_byte`, next.

```diff
-def recover_byte(prefix: bytes, target_block: bytes) -> bytes:
+def recover_byte(
+   prefix: bytes, target_block: bytes, target_index: int, block_size: int
+) -> bytes:
-   block_size = len(prefix) + 1  # operate under assumption that only 1 byte is unknown
-
    for byte_as_int in range(0x100):
        byte = byte_as_int.to_bytes(1, byteorder="little")
        guess = prefix + byte

        ciphertext = oracle.encrypt(guess)
-       first_block = ciphertext[:block_size]
+       guess_block = ciphertext[target_index * block_size:(target_index + 1) * block_size]
      
-       if first_block == target_block:
+       if guess_block == target_block:
            return byte
    
    raise ValueError(
        f"Could not recover byte with prefix {prefix} and target block {target_block}"
    )
```

The main change here is that we cannot assume that the first block is the block that
the attacker (AKA us) controls. We must instead use the first block after the random
prefix as the attacker controlled block that we can use to generate ciphertexts for
our search space. This boils down to some extra parameters that help us index that
block correctly.

The last change we need to make is in how we detect the size of the target message.

```diff
-def detect_appended_bytes_length() -> int:
+def detect_appended_bytes_length(random_prefix_length: int) -> int:
    data = b''
    initial_len = cur_len = len(oracle.encrypt(data))

    while cur_len == initial_len:
        data += b'A'
        cur_len = len(oracle.encrypt(data))
    
    padding_bytes = len(data)
-   return initial_len - padding_bytes
+   return initial_len - padding_bytes - random_prefix_length
```

This is also fairly straight forward. We just have to account for the random prefix
in our calculation. Since we already derive the length of the random prefix in the
`recover_appended_message` function we just pass it as a parameter and then subtract
the length from the value we get using the challenge 12 algorithm. Putting it all
together we arrive at the following solution.

```python
from base64 import b64decode
from os import urandom
from random import randint
from typing import Tuple

from challenge08 import is_encrypted_in_ecb_mode
from challenge11 import aes_ecb_encrypt

oracle = None


class EncryptionOracle:
    def __init__(self, appended: bytes):
        self.key = urandom(16)  # 128 bit key for AES
        self.appended = appended
        prefix_bytes = randint(1, 100)
        self.prefix = urandom(prefix_bytes)
    
    def encrypt(self, data: bytes) -> bytes:
        return aes_ecb_encrypt(self.prefix + data + self.appended, self.key)


def get_pad_length_and_start_block(block_size: int) -> Tuple[int, int]:
    repeating_bytes = (3 * block_size - 1) * b'\x00'
    ciphertext = oracle.encrypt(repeating_bytes)
    assert is_encrypted_in_ecb_mode(ciphertext)

    target_block_index = -1
    for i in range(len(ciphertext) // block_size - 1):
        block_start = i * block_size
        block_end = next_block_start = block_start + block_size
        next_block_end = next_block_start + block_size

        block = ciphertext[block_start:block_end]
        next_block = ciphertext[next_block_start:next_block_end]

        if block == next_block:
            target_block_index = i
            break

    while is_encrypted_in_ecb_mode(ciphertext):
        repeating_bytes = repeating_bytes[:-1]
        ciphertext = oracle.encrypt(repeating_bytes)
    
    pad_length = len(repeating_bytes) - (block_size * 2 - 1)
 
    return pad_length, target_block_index


def detect_block_size() -> int:
    data = b'A'
    initial_len = cur_len = len(oracle.encrypt(data))

    while cur_len == initial_len:
        data += b'A'
        cur_len = len(oracle.encrypt(data))

    return cur_len - initial_len


def detect_appended_bytes_length(random_prefix_length: int) -> int:
    data = b''
    initial_len = cur_len = len(oracle.encrypt(data))

    while cur_len == initial_len:
        data += b'A'
        cur_len = len(oracle.encrypt(data))
    
    padding_bytes = len(data)
    return initial_len - padding_bytes - random_prefix_length


def recover_byte(
    prefix: bytes, target_block: bytes, target_index: int, block_size: int
) -> bytes:
    for byte_as_int in range(0x100):
        byte = byte_as_int.to_bytes(1, byteorder="little")
        guess = prefix + byte

        ciphertext = oracle.encrypt(guess)
        guess_block = ciphertext[target_index * block_size:(target_index + 1) * block_size]
        
        if guess_block == target_block:
            return byte
    
    raise ValueError(
        f"Could not recover byte with prefix {prefix} and target block {target_block}"
    )


def recover_appended_message() -> bytes:
    known_bytes = b''

    block_size = detect_block_size()
    pad_length, start_block = get_pad_length_and_start_block(block_size)
    random_prefix_length = start_block * block_size - pad_length
    target_length = detect_appended_bytes_length(random_prefix_length)

    current_block = start_block
    constant_pad_bytes = b'A' * pad_length

    while len(known_bytes) != target_length:
        block_start = current_block * block_size
        block_end = block_start + block_size

        a_bytes = block_size - (len(known_bytes) % block_size) - 1
        prefix = constant_pad_bytes + (b'A' * a_bytes)

        ciphertext = oracle.encrypt(prefix)
        target_ciphertext_block = ciphertext[block_start:block_end]

        if current_block == start_block:
            lookup_prefix = prefix + known_bytes
        else:
            lookup_prefix = constant_pad_bytes + known_bytes[-(block_size - 1):]

        known_bytes += recover_byte(
            lookup_prefix, target_ciphertext_block, start_block, block_size
        )

        if len(known_bytes) % block_size == 0:
            current_block += 1

    return known_bytes


def challenge14():
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
