---
layout: post
title:  "Cryptopals Set 1, Challenge 3"
author: Anton Kueltz
tag: cryptopals
---

Finally some code breaking! We are [tasked with deciphering some data that
has been encrypted under a single byte key](https://cryptopals.com/sets/1/challenges/3).
The encryption is done via the XOR operation from the last challenge, granted
this time the key is a single byte so we iteratively XOR the key byte against
the enrypted data to get a candidate plaintext.

The solution is broken into two parts - scoring and book keeping. Scoring is
the more interesting of the two (for a cryptographer at least). Considering that
the range of possible characters in a candidate plaintext can be any character
represented by encoding 0x00 through 0xff we'll find that most of the candidates end
up being gibberish that encode to characters that are not letters. So a good scoring
method would be "score candidate plaintexts with lots of letters higher than those
with few letters". We can even do a bit better. We can score those plaintexts that
have common english letters higher than those that don't. Our reasoning being that
common english letters are on average more likely to appear, and thus correlate more
closely to a plaintext that is valid english.

The book keeping is just a brute force attack. Since the key is a single byte we only
have to check 2^8 = 256 possible keys. Childs play for a computer. For each key we 
score the resulting candidate plaintext and, if the score is a new high score, we mark
that key as the best guess for the true key.

Technically we already know the plaintext when we find the key and can just return that
along with the key, but for future problems an interface that returns only the key is 
handier. Plus the extra decryption operation doesn't change our runtime complexity, the
core of the computational complexity here is in the brute force attack which is O(2^n),
where n is the size of the key in bits.

```python
from binascii import unhexlify


def score(chars: bytes) -> int:
    points = 0
    most_freq_letters = b'etaoinhs'

    for c in chars:
        if c in most_freq_letters:
            points += 1

    return points


def find_single_byte_key(ctxt: bytes) -> int:
    best_key = None
    best_score = -1

    for key in range(0xff + 1):
        ptxt = bytes([(c ^ key) for c in ctxt])
        key_score = score(ptxt)

        if key_score > best_score:
            best_key = key
            best_score = key_score

    return best_key


def single_byte_cipher(ctxt: bytes) -> bytes:
    key = find_single_byte_key(ctxt)
    return bytes(map(lambda c: key ^ c, ctxt))


def challenge03():
    ctxt = unhexlify(
        b'1b37373331363f78151b7f2b783431333d'
        b'78397828372d363c78373e783a393b3736'
    )
    ptxt = single_byte_cipher(ctxt)
    print(ptxt)
```