---
title: "Tenable CTF 2022"
header:
  teaser: /assets/images/2022-tenable-ctf/tenable-ctf-logo.png
excerpt_separator: "<!--more-->"
categories:
  - CTF
tags:
  - Cryptograhpy
---

I competed in Tenable's 2022 CTF with the [Hack South](https://hacksouth.africa/) CTF team on 8 May 2021. This is an 4-day CTF hosted by the company behind the well-known Nessus scanner. I was busy with a Hack The Box pro lab and some of my team members were too busy with work to play. We still ended up placing 59th overall. The top 100 teams qualify for a free Tenable CTF T-shirt 👕, so I am happy.

![Tenable CTF 2022 Result](/assets/images/2022-tenable-ctf/hack-south-result.png){:.align-center}

Here is a write-up for the most interesting (to me) of the nine challenges I solved.<!--more-->

## WiFi Password Of The Day

> Our network admin likes to change the WiFi password daily. He's afraid someone might crack it :) If you know the right AES key you can request the current wifi password from the service listed below.
> Attached is a testing version of the service. Perhaps there is a flaw you can exploit to retrieve the password?

### Service Code

The following source code was provided. The same code runs on the target, only with a different flag and encryption key.

```python
import zlib
import json
import base64
from Crypto.Cipher import AES
from twisted.internet.protocol import Factory, Protocol
from twisted.internet import reactor

# wifi password
current_wifi_password = "flag{test_123}"

# 128 bit key
encryption_key = b'testing123456789'

def encrypt_wifi_data(user):
    global current_wifi_password, encryption_key
    wifi_data = {"user:": user,
                 "pass:": current_wifi_password}
    to_send = json.dumps(wifi_data)
    msg = zlib.compress(to_send.encode('utf-8'))
    text_padded = msg + (AES.block_size - (len(msg) % AES.block_size)) * b'\x00'
    iv = 16 * b'\x00'
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    cipher_enc = cipher.encrypt(text_padded)
    return cipher_enc

class Challenge(Protocol):

    def dataReceived(self, data):
        username = data.strip()
        data = encrypt_wifi_data(username.decode('utf-8'))
        self.transport.write(base64.b64encode(data) + b'\r\n')
        self.transport.write(b"Enter username: ")

    def connectionMade(self):
        self.transport.write(b"Welcome to Wifi Password of the Day Server\r\n")
        self.transport.write(b"Enter username: ")

    def __init__(self, factory):
        self.factory = factory
        self.debug = True

class ChallengeFactory(Factory):
    protocol = Challenge

    def buildProtocol(self, addr):
        return Challenge(self)

reactor.listenTCP(1234, ChallengeFactory())
reactor.run()
```

### Process

The server requests a username, puts it into a JSON object together with the flag, compresses the JSON string with zlib, and then encrypts the compressed bytes. The encrypted bytes are base64 encoded and returned to us.

The encryption uses AES in CBC mode with a 128-bit key and 0 IV. This did not look like the target. The compression step caught my eye because I had previously heard about the "CRIME" (Compression Ratio Info-leak Made Easy) vulnerability. With my very naive understanding of compression, I thought if there are repeating patterns in uncompressed data, then compression can "group" those patterns into a dictionary. On the other hand, a byte stream cannot be compressed well when it is truly random with no repeating patterns. E.g. if the same flag (or any other text) occurs twice in the uncompressed data, then it can be added to a compressed file's dictionary once and referenced.

I tested this theory by sending `flag{` and `!@#$%` for the username and compared the lengths of the two outputs. The CTF's flag format is `flag{<something>}`, so the `flag{` input *should* also be in the actual flag. It worked and held up when I tested it a few times: With username `flag{`, the output size is always one block smaller than when I used five special characters.

![Tenable CTF 2022 Result](/assets/images/2022-tenable-ctf/username-test.png){:.align-center}

I could use this behaviour to iteratively guess and verify the next character in the flag text! If the output adds an additional block, it means the compression worsened and the guess was likely wrong. If the size remained the same, then the guess was likely correct. I played around with inputs to determine exactly how much padding was needed to enable guessing one character at a time. Appending four special characters to my guess worked perfectly.

|Guess|Username|Blocks|
|-|-|-|
|a|`flag{a!@#^`|5|
|b|`flag{b!@#^`|5|
|c|`flag{c!@#^`|4|
|ca|`flag{ca!@#^`|5|
|cb|`flag{cb!@#^`|5|
|c...|...|5|
|c0|`flag{c0!@#^`|4|

My solution code automated above process to guess the next character until it found `}` at the end the flag text.

```python
from pwn import *
import base64
import string

pad = '!@#^'
chars = string.ascii_letters + string.digits + '_}'
known = 'flag{'

def send_guess(t, guess):
    guess = '%s%s%s' % (known, guess, pad)
    t.sendafter(b'username: ', guess.encode())
    res = base64.b64decode(t.recvline().strip(b'\n'))
    size = len(res) // 16
    return size == 4

t = remote('0.cloud.chals.io', 28931)

while True:
    for c in chars:
        if send_guess(t, c):
            known += c
            print(known)
            if c == '}': exit()
            else: break
```

![Flag Guess Iterations](/assets/images/2022-tenable-ctf/flag-iterations.png){:.align-center}
