---
layout: post
title: "More OCB2 Forgeries"
author: Anton Kueltz
tag: practical-exploit
---

This post builds on the content and code from the [prior post about OCB2 mode forgeries](/forging-ocb2-tags/).
If you haven't read that post I would recommend starting there. In this post we'll explore
how to do some further forgeries of OCB2 and also dive a little into code refactoring so that
our implementation from the original post becomes a little more general.

In the previous post we implemented the attack in section 4.1. of [this paper](https://eprint.iacr.org/2018/1040.pdf),
the "Minimal Example of Forgery". Today we're going to extend our code from that attack to
implement section 4.2, "Forgery of Longer Messages". The first steps here will be refactoring our
code such that common logic between the two forgers is decoupled from the original minimal forger.

For the refactoring approach we observe that the pattern for generating forgeries in both the minimal
and longer setting is -
1. Generating chosen plaintext inputs
2. Encrypting the chosen inputs via the oracle
3. Modifying the ciphertext and tag from step 2 to obtain a forgery
4. Validating the forgery from step 3 via the oracle

The differences between the minimal and longer forger are in steps 1 and 3. This means that we can model
a generic forger as an abstract class which requires child classes to implement methods for steps 1 and 3 and
which implements the high level control flow (i.e. the combination of steps 1-4).
```python
from abc import ABC, abstractmethod
from binascii import hexlify
from typing import Tuple

from oracle import Oracle


class Forger(ABC):
    @abstractmethod
    def generate_inputs(self) -> Tuple[bytes, bytes]:
        pass

    @abstractmethod
    def generate_forgery(self, m: bytes, c: bytes) -> Tuple[bytes, bytes]:
        pass

    def forge_tag(self):
        # step 1
        m, a = self.generate_inputs()
        print(f'Generated chosen plaintext:\n{hexlify(m)}\n')

        # step 2
        oracle = Oracle()
        t, c = oracle.encrypt(m, a)
        print(
            f'Encryption Oracle returned -\n'
            f'Ciphertext: {hexlify(c)}\n'
            f'Tag: {hexlify(t)}\n'
        )

        # step 3
        t_, c_ = self.generate_forgery(m, c)
        print(
            f'Forgery -\n'
            f'Ciphertext: {hexlify(c_)}\n'
            f'Tag: {hexlify(t_)}\n'
        )

        # step 4
        valid, _ = oracle.decrypt(a, c_, t_)
        print(f'Forged tag is valid: {valid}')
```

Note that the oracle remains its own `Oracle` class with no changes. We also keep the `encode_length` and
`xor` functions in a module meant for common functionality. We can then implement our original minimal
forger in this new approach by extending the `Forger` class.
```python
from os import urandom
from typing import Tuple

from common import Forger, encode_length, xor

BLOCKSIZE = 16  # bytes


class MinimalForger(Forger):
    def generate_inputs(self) -> Tuple[bytes, bytes]:
        m = encode_length(BLOCKSIZE * 8) + urandom(BLOCKSIZE)
        return m, b''

    def generate_forgery(self, m: bytes, c: bytes) -> Tuple[bytes, bytes]:
        c_ = xor(c[:BLOCKSIZE], encode_length(BLOCKSIZE * 8))
        t_ = xor(m[BLOCKSIZE:], c[BLOCKSIZE:])
        return t_, c_


if __name__ == '__main__':
    forger = MinimalForger()
    forger.forge_tag()
```

Our file structure now looks a little more modular in anticipation of adding the longer forger.
```
ocb-forger/
+-- common.py   # abstract forger class and common methods
+-- minimal.py  # implementation of the minimal forgery
+-- oracle.py   # OCB2 mode encryption/decryption oracle
```

We can convince ourselves that our minimal attack still works by running `python minimal.py`.
```bash
$ python3 minimal.py
Generated chosen plaintext:
b'00000000000000000000000000000080ad54a7b454aca10a84c999260dcdd279'

Encryption Oracle returned -
Ciphertext: b'314c4881dd8151ecc816ddf719c9fa84cf57dc92afe5cc9c926c6d50ceb16660'
Tag: b'b4e4c1eaf1f671f19de2e63c4c4e50ae'

Forgery -
Ciphertext: b'314c4881dd8151ecc816ddf719c9fa04'
Tag: b'62037b26fb496d9616a5f476c37cb419'

Forged tag is valid: True
```

To add the longer forger we just need to add a class that inherits the base `Forger` class and implements
the `abstractmethod`s from that class. The input generation for longer forgeries is fairly straightforward.
We take generate a sequence of random blocks as the input, with the only criteria being that the penultimate
block is the encoded length of the block size (in bits). In the implementation below we randomly sample the
the length of the message to be anywhere between 4 and 12 blocks, but these  criteria are somewhat arbitrary.
The message length must be at least 4 blocks for the attack to work, but the upper bound is there only for
the sake of somewhat readable output and so that the attack does not spend a bunch of time generating a huge
amount of random bytes. No additional data is needed for the longer attack so an empty byte sequence is used.
```python
from os import urandom
from random import randint
from typing import Tuple

from common import Forger, encode_length

BLOCKSIZE = 16  # bytes


class LongerForger(Forger):
    def generate_inputs(self) -> Tuple[bytes, bytes]:
        self.blocks = randint(2, 10)  # choose random amount of multiple blocks
        m = urandom(BLOCKSIZE * self.blocks)
        m += encode_length(BLOCKSIZE * 8)  # bits
        m += urandom(BLOCKSIZE)
        return m, b''
```

The longer forgery is a bit trickier than the minimal forgery. In this case we need to modify the ciphertext
such that all blocks up until the penultimate block are the same, the penultimate block is modified, and the
final block is truncated (so if our original ciphertext had length `m` the modified one has length `m-1`). The
modification to the `m-1`th block is that we take the existing `m-1`th block in the ciphertext and XOR it with
all of the plaintext blocks up to (but not including) the `m-1`th plaintext block. We then also XOR in the encoded
length of the block size (in bits). Finally, we forge the tag. The tag is simply the XOR of the last plaintext
block with the last block of the original ciphertext.
```python
from typing import Tuple

from common import xor


class LongerForger(Forger):
    def generate_forgery(self, m: bytes, c: bytes) -> Tuple[bytes, bytes]:
        c_ = c[:self.blocks * BLOCKSIZE]  # self.blocks is set in generate_inputs

        last_block = b'\x00' * BLOCKSIZE
        for i in range(self.blocks):
            m_i = m[i * BLOCKSIZE:(i + 1) * BLOCKSIZE]
            last_block = xor(last_block, m_i)
        c_m1 = c[self.blocks * BLOCKSIZE:(self.blocks + 1) * BLOCKSIZE]
        last_block = xor(last_block, c_m1)
        last_block = xor(last_block, encode_length(BLOCKSIZE * 8))  # bits

        c_ += last_block

        m_m = m[(self.blocks + 1) * BLOCKSIZE:]
        c_m = c[(self.blocks + 1) * BLOCKSIZE:]
        t_ = xor(m_m, c_m)

        return t_, c_
```

We then have a complete forger in `longer.py` that we can run.
```python

from os import urandom
from random import randint
from typing import Tuple

from common import Forger, encode_length, xor

BLOCKSIZE = 16  # bytes


class LongerForger(Forger):
    def generate_inputs(self) -> Tuple[bytes, bytes]:
        self.blocks = randint(2, 10)  # choose random amount of multiple blocks
        m = urandom(BLOCKSIZE * self.blocks)
        m += encode_length(BLOCKSIZE * 8)  # bits
        m += urandom(BLOCKSIZE)
        return m, b''

    def generate_forgery(self, m: bytes, c: bytes) -> Tuple[bytes, bytes]:
        c_ = c[:self.blocks * BLOCKSIZE]

        last_block = b'\x00' * BLOCKSIZE
        for i in range(self.blocks):
            m_i = m[i * BLOCKSIZE:(i + 1) * BLOCKSIZE]
            last_block = xor(last_block, m_i)
        c_m1 = c[self.blocks * BLOCKSIZE:(self.blocks + 1) * BLOCKSIZE]
        last_block = xor(last_block, c_m1)
        last_block = xor(last_block, encode_length(BLOCKSIZE * 8))  # bits

        c_ += last_block

        m_m = m[(self.blocks + 1) * BLOCKSIZE:]
        c_m = c[(self.blocks + 1) * BLOCKSIZE:]
        t_ = xor(m_m, c_m)

        return t_, c_


if __name__ == '__main__':
    forger = LongerForger()
    forger.forge_tag()
```

We can verify the longer forger works via `python longer.py`.
```bash
$ python3 longer.py
Generated chosen plaintext:
b'068066095f694aa7ca5da9f2baf7a814adf8029507d3a820dfe1194079c45a2a46fa5896fa8b572b38e92792d8aa4d8a3bc0fbf9b04ed231a07ecae9898fa483000000000000000000000000000000800aa4aba2ac6c6f2f624052e1db880daa'

Encryption Oracle returned -
Ciphertext: b'1aeb428b7bf8dddc47a25f9315a4804f7f63b8673dcab144662b4617b491e48bc7d12666328214ff201c6d94496d17451f99353c8fa653c65828f4a7f93f5a31f8887452b0f70f11874583b47fe4bb875dab9418791f8b65a94cce8ac3c6a76c'
Tag: b'cbb2e20b4a6a532cf4f1308eb3be1091'

Forgery -
Ciphertext: b'1aeb428b7bf8dddc47a25f9315a4804f7f63b8673dcab144662b4617b491e48bc7d12666328214ff201c6d94496d17451f99353c8fa653c65828f4a7f93f5a312ecab3a1a288688c0a6ede7dedf2a030'
Tag: b'570f3fbad573e44acb0c9c6b184eaac6'

Forged tag is valid: True
```

Note that the advantage of our refactor is that we did not need to have the new forger have any awareness of
the oracle or of how to stitch together the logic for generating inputs and forgeries. That framework was taken
care of by our common code and the only code we needed to add for the longer forger were the implementation details
specific to the longer forgery described in the paper.