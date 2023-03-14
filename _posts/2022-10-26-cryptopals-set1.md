---
layout: post
title: "Cryptopals Set 1: Basics"
author: Anton Kueltz
tag: cryptopals
---

In this [first set](https://cryptopals.com/sets/1) we cover some of the
fundamental building blocks we will use for many of the coming challenges.
We also warm up our cryptanalysis skills by breaking a couple classical
cipher systems.

* TOC
{:toc}

# Challenge 1: Convert Hex to Base64

To start we are [tasked with decoding some hex data and encoding the
resulting bytes in base64](https://cryptopals.com/sets/1/challenges/1). 
Not much cryptography happening here, but some useful utilities since 
we'll be given raw byte data (keys, ciphertexts, etc) in encoded form
later on. Python has everything we need to encode and decode various 
representations of bytes so all we have to do is chain together a couple
calls from the standard library.

```python
from base64 import b64encode
from binascii import unhexlify


def hex_to_b64(hex_str: bytes) -> bytes:
    raw = unhexlify(hex_str)
    return b64encode(raw)


def challenge01():
    hex_data = b'49276d206b696c6c696e6720796f757220627261696e206c' \
               b'696b65206120706f69736f6e6f7573206d757368726f6f6d'
    b64_data = hex_to_b64(hex_data)
    print(b64_data)
```

# Challenge 2: Fixed XOR

In this second challenge we are [tasked with computing the XOR of two
byte sequences](https://cryptopals.com/sets/1/challenges/2). First we
need to decode the hex encoded bytes, which we learned how to do in
the first challenge. Then we can operate on raw bytes and implement the 
XOR. The XOR operator is implemented via `^` in python. We can utilize 
the fact that the elements returned when iterating over a byte sequence 
in python can be interpreted as the integer  representation of that byte 
(e.g. `b'\xff'` => `255`). `^` operates on  integers so we grab elements 
pairwise from the two byte sequences we wish to XOR, apply `^` to the 
pairs, and then recombine the results into a byte sequence. `zip` 
(getting elements from two sequences pairwise) and list comprehensions 
(combining our results back into a sequence) make this easy to 
concisely implement.

```python
from binascii import hexlify, unhexlify


def xor(buf1: bytes, buf2: bytes) -> bytes:
    return bytes([b1 ^ b2 for (b1, b2) in zip(buf1, buf2)])


def challenge02():
    left = unhexlify(b'1c0111001f010100061a024b53535009181c')
    right = unhexlify(b'686974207468652062756c6c277320657965')
    xored = xor(left, right)
    print(hexlify(xored))
```

# Challenge 3: Single-byte XOR Cipher

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

# Challenge 4: Detect Single-character XOR

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
    with open('4.txt', 'rb') as f:
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

# Challenge 5: Implement Repeating-key XOR

Keys longer than one byte! We're starting to slowly but surely move toward challenges
where we can't brute force the key space quickly. Here we are [tasked with implementing
a repeating key XOR](https://cryptopals.com/sets/1/challenges/5), meaning we repeat the
key to be the length of the plaintext and then xor the two together.
```
Burning `em
|||||||||||
ICEICEICEIC
```
We make this a little more efficient by noting that the corresponding key byte for a
plaintext byte at index `i` is the key byte at index `i % len(key)`. This is because the
key repeats every `len(key)` bytes.

```python
from binascii import hexlify


def repeating_key_xor(intxt: bytes, key: bytes) -> bytes:
    outtxt = []

    for i, c in enumerate(intxt):
        key_index = i % len(key)
        outtxt.append(c ^ key[key_index])

    return bytes(outtxt)


def challenge05() :
    plaintext = b'Burning \'em, if you ain\'t quick and nimble ' \
                b'I go crazy when I hear a cymbal'
    key = b'ICE'
    ctxt = repeating_key_xor(plaintext, key)
    print(hexlify(ctxt))
```

# Challenge 6: Break Repeating-key XOR

This challenges greets us with "It is officially on, now.". Indeed, in this 
challenge we are tasked with [breaking a ciphertext that has been encrypted
with the repeating key XOR](https://cryptopals.com/sets/1/challenges/6) 
from challenge 5. The key length is unknown so we
will first need to determine that. Once we have done that we will reduce the
problem to multiple single byte key ciphers (which we already know how to
break). More on that later, first let's talk about figuring out the key
size.

The first utility function we need to implement is `hamming_distance`, which
tells us how many bits differ between two byte sequences. The way we do this
is to take the XOR (pairwise, by byte) of the two sequences. The result of
the XOR will have a 1 bit at indices where the sequences differ and 0 bit
where they are the same. We can then use the newly introduced 
`int.bit_count` from python3.10 to count the number of 1 bits in the XOR 
result, which is the Hamming distance of the two sequences. We then verify 
that the test vector we are given in the problem produces the expected
output -

```python
In [1]: from challenge06 import hamming_distance

In [2]: hamming_distance(b'this is a test', b'wokka wokka!!!')
Out[2]: 37
```

Next we need to figure out how long the key actually is. The problem
statement tells us that to do this we can break the ciphertext into
blocks that are the size of a candidate key. We then find the Hamming
distance between those blocks and normalize it. Low values in this score
correlate to better candidates for key sizes. One thing the problem doesn't
get into is why this is. Consider we have a key that is three bytes long, 
let's say `b"KEY"`. Suppose we have a plaintext of `b"HIDDENSECRET"`. Then
our ciphertext is as follows -

```python
b"KEY" ^ b"HID" + b"KEY" ^ b"DEN" + b"KEY" ^ b"SEC" + b"KEY" ^ b"RET"
```

Note that when we compute the Hamming distance of the blocks against one
another the keys cancel out.

```python
b"KEY" ^ b"HID" ^ b"KEY" ^ b"DEN" = b"HID" ^ b"DEN"
```

This follows from some basic properties of XOR, namely -
* a ^ a = 0
* a ^ 0 = a

So when we pick the right key size our Hamming distance calculation is doing
the distance between the plaintext blocks. If we have a plaintext that is in
English (and make some sane assumptions about character encoding) then our
Hamming distance should be low, because most characters in English have very
similar bit representations, so their XOR is mostly 0 bits. Note that if we
pick the wrong key size this does not apply as the key bytes will not cancel
one another out. With wrong key sizes we expect a much more random
distribution of bytes being XORed in the Hamming distance calculation.

Once we have the top candidates for key sizes we apply the same principles
that we used to break single byte keys. We reduce each key byte of the
candidate key size into its own single byte cipher to be solved. We do this
by taking all the ciphertext bytes that would be encrypted under that key
byte, concatenate them, and create a new ciphertext that we already have
techniques for breaking. Once we have a candidate for each key byte we
produce the corresponding plaintext and score it. The highest score, as
always, will be our best candidate for the plaintext.

```python
from base64 import b64decode
from itertools import combinations
from typing import List

from challenge03 import score, find_single_byte_key
from challenge05 import repeating_key_xor


def hamming_distance(buf1: bytes, buf2: bytes) -> int:
    distance = 0

    for c1, c2 in zip(buf1, buf2):
        diff = c1 ^ c2
        distance += diff.bit_count()

    return distance


def _best_key_lengths(data: bytes) -> List[int]:
    dist_and_ksize = []

    for ksize in range(2, 41):
        blocks = []
        for block_start in range(0, ksize * 4, ksize):
            block_end = block_start + ksize
            blocks.append(data[block_start:block_end])

        distance = 0
        for block1, block2 in combinations(blocks, 2):
            distance += hamming_distance(block1, block2)

        dist_and_ksize.append((distance / ksize, ksize))

    dist_and_ksize.sort()
    return [ksize for (_, ksize) in dist_and_ksize[:3]]


def break_repeating_key(data: bytes) -> bytes:
    keylens = _best_key_lengths(data)
    best_score, ptxt = 0, b''

    for keylen in keylens:
        key = []
        blocks = [[] for _ in range(keylen)]

        for i, c in enumerate(data):
            blocks[i % keylen].append(c)
        blocks = map(bytes, blocks)

        for block in blocks:
            key.append(find_single_byte_key(block))
        key = bytes(key)

        txt = repeating_key_xor(data, key)
        cur_score = score(txt)

        if cur_score > best_score:
            best_score = cur_score
            ptxt = txt

    return ptxt


def challenge06():
    with open('6.txt', 'rb') as f:
        data = b64decode(f.read().replace(b'\n', b''))
        print(break_repeating_key(data))
```

# Challenge 7: AES in ECB Mode

In [this challenge](https://cryptopals.com/sets/1/challenges/7)
we get our first usage of modern cryptography, namely
the AES cipher. Python doesn't implement AES as part of the standard 
library so we can either implement it ourselves or use a third party
library. Implementing it ourselves would be useful if we're attacking
the internals of the cipher, such as doing cryptanalysis of the S-boxes,
but for these challenges we'll attack constructions that are one or more
"layers" higher than AES. That is to say, we'll attack vulnerable
protocols that build on AES, but where AES is not part of the attack
vector.

That being said, we'll be using
[`pycryptodome`](https://www.pycryptodome.org/) for most of our 
primitives that we don't implement ourselves. Why? Mainly because when I 
first solved these challenges years ago I used `pycrypto` and
`pycryptodome` has a compatible API and is still actively maintained.
The `cryptography` library is also probably just fine for this, although
I find primitives being under the `hazmat` category in their package
layout a bit obnoxious.

The only other thing to note here is that the block cipher mode we're
using is electronic codebook (ECB), which is somewhat famous for
[poorly encrypting images of penguins](https://words.filippo.io/the-ecb-penguin/).
This mode is quite simple, you take a block (128 bits in AES) of
plaintext, feed it into AES, get the ciphertext and rinse and repeat
until you're out of plaintext blocks. The final ciphertext is just
the concatenation of the ciphertext blocks. Wikipedia also has a nice
[diagram](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB)
describing this mode if you're a visual learner.

```python
from base64 import b64decode

from Crypto.Cipher import AES


def aes_ecb_decrypt(ctxt: bytes, key: bytes) -> bytes:
    ptxt = b''
    cipher = AES.new(key, AES.MODE_ECB)

    for block in range(len(ctxt) // AES.block_size):
        start = block * AES.block_size
        end = start + AES.block_size
        ptxt += cipher.decrypt(ctxt[start:end])

    return ptxt


def challenge07():
    key = b'YELLOW SUBMARINE'

    with open('7.txt', 'rb') as f:
        data = b64decode(f.read().replace(b'\n', b''))
        print(aes_ecb_decrypt(data, key))
```

# Challenge 8: Detect AES in ECB Mode

In the final challenge of set 1 
[we need to identify which ciphertext has been encrypted using ECB mode](https://cryptopals.com/sets/1/challenges/8). Recall that ECB mode will always
produce the same ciphertext block for two equal plaintexts blocks, 
provided that they are encrypted under the same key. So an easy way to check
for ECB mode is to see if there are two equal blocks in a ciphertext. Note
that we do not have to perform any decryption operations for us to be able
to identify the ciphertext encrypted in ECB mode.

```python
from binascii import hexlify, unhexlify
from typing import Optional

from Crypto.Cipher import AES


def is_encrypted_in_ecb_mode(ctxt: bytes) -> bool:
    blocks = set()

    for block in range(len(ctxt) // AES.block_size):
        start = block * AES.block_size
        end = start + AES.block_size
        block = ctxt[start:end]

        if block in blocks:
            return True

        blocks.add(block)

    return False


def challenge08():
    with open('8.txt', 'rb') as f:
        ctxts = [unhexlify(txt) for txt in f.read().split(b'\n')]

    for ctxt in ctxts:
        if is_encrypted_in_ecb_mode(ctxt):
            print(hexlify(ctxt))
```

## Appendix

While it is theoretically possible for ciphertexts encrypted with other block
cipher modes to have equal blocks, the probability of this happening is
so infinitesimal that it's not worth considering for this problem. To give a
more concrete example, consider
[CBC mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)).
If we assume that AES is a pseudorandom function, and that the IV is randomly
sampled, then we can also state that each ciphertext block is a randomly
sampled value from the function image (all possible 128 bit numbers) that is
independent of the plaintext block. We can then apply the 
[birthday paradox](https://en.wikipedia.org/wiki/Birthday_problem)
to determine how likely a collision (two equal blocks) is in such a ciphertext.
Given that members of a group can have any of `n` possible values, and there are
`k` members in the group, the probability that no two members have the same
value assigned to them is
```
(1 / n)^k * (n * (n-1) * (n-2) * ... * (n-k+1))
```
In our case the range of possible values is all 128 bit numbers, so `n=2^128`
possible values. If we have a `k=1000000` block plaintext then the probability of
two equal ciphertext blocks would be
```python
In [1]: n = 2**128

In [2]: k = 1000000

In [3]: from functools import reduce

In [4]: reduce(lambda x, y: x * (y / n), range(n, n-k, -1), 1.0)
Out[4]: 1.0
```
Python can't properly represent values this close to 1 due to floating point
representation limitations so let's reduce the possible values to `n=2^64`, which 
is about `1.94 * 10^19` times smaller than `n=2^128`. In this case the 
probability of no two equal blocks is
```python
In [1]: n = 2**64

In [2]: k = 1000000

In [3]: from functools import reduce

In [4]: reduce(lambda x, y: x * (y / n), range(n, n-k, -1), 1.0)
Out[4]: 0.9999999728949818
```
This means the probability of there not being a collision in a ciphertext that
is a million blocks long, using a block cipher with a function image of size `2^64`,
is 99.99999%. Now imagine how many more nines the probability has when we expand
the function image size by a factor of `1.94 * 10^19`. Given how incomprehensibly
unlikely this scenario is we do not take it into consideration for our approach
to identifying ciphertexts encrypted in ECB mode.
