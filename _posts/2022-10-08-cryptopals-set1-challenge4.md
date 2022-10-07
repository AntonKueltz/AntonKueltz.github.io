---
layout: post
title:  "Cryptopals Set 1, Challenge 4"
---

For this challenge we are [tasked with building on top of challenge 3 and
identifying which ciphertext in a collection of ciphertexts decrypts to a
valid (english) plaintext](https://cryptopals.com/sets/1/challenges/4). The
keys are again a single byte and the encryption is again done using XOR. We
reuse the logic from challenge 3 to find the best (most common english letters)
plaintext for each ciphertext. We then add another layer on top of that and
score each of the best plaintexts, returning the one with the highest score.

Our runtime complexity is slight higher than the last problem now, O(2^n * m)
where n is the number of bits in the key and m is the number of ciphertexts.
It's also worth noting that reading the entire text file and splitting it into
a list of ciphertexts to iterate over probably isn't the most efficient. If we
had a huge list then reading line by line until the end of the buffer would be
better. In this case the list is small so this implementation works well
enough and saves us having to strip newlines and identifying where the EOF is.

```python
from binascii import unhexlify

from challenge03 import score, single_byte_cipher


def challenge04():
    with open('Data/4.txt', 'rb') as f:
        high_score = 0
        ptxt = None

        for ctxt in f.read().split(b'\n'):
            raw = unhexlify(ctxt)
            txt = single_byte_cipher(raw)
            points = score(txt)

            if points > high_score:
                high_score = points
                ptxt = txt

    print(ptxt)
```