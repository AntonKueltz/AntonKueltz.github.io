---
layout: post
title:  "Hey, What's The Deal With All These Cryptopals Posts?"
---

Great question. I did these challenges about a decade ago while I was first
learning python and getting into cryptography. They've since become my go
to programming exercises for learning a new language. I think they make a good
candidate for this because the challenges facilitate becoming accustomed with
a language's standard lib (I/O, encoding, data structures, crypto (duh), etc)
and are also complex enough that you can make use of a lot of the syntax and
syntactic sugar that a language has to offer.

I somewhat recently went back and rewrote all 7 sets in python3 (originally these 
were python2.7) and thought it would be fun to write about the problem solving
process for how I approached these challenges. Additionally, there were also some
cases where new language features in python3 made the implementation cleaner and
I thought it would be fun draw some attention to those cases.

These implementations aren't perfect, they're likely not the most efficient and
might forego some cleverness available in the cryptanalyst's toolbox. What they
are, hopefully, is readable and efficient _enough_. They're certainly efficient
enough to solve the challenges on my same old laptop that I wrote the original 
solutions on.

A final note as far as "cheating" goes. These posts aren't intended ruin the fun
for anyone solving these challenges for the first time. If anything, there are
already tons of solutions available online for these. Copy pasting code doesn't
help with learning so it's really just cheating yourself if you do that. These
posts are intended for folks to learn a bit about python and to also see another
perspective on solving these challenges. If you learn something new from reading
them then they have served their purpose.
