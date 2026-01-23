# ChaCha20/Poly1305 AEAD Implementation

## Overview

This project implements the ChaCha20 stream cipher and ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data) construction as specified in [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439).

The implementation consists of two main parts:
- **Part 1**: ChaCha20 stream cipher for encryption/decryption
- **Part 2**: ChaCha20-Poly1305 AEAD for authenticated encryption with associated data

## Requirements

- Python 3.x
- No external dependencies (uses only Python standard library)

## Installation

Make sure the script is executable:

```bash
chmod +x chacha20.py aead_wrap.py aead_unwrap.py
```

## Part 1: ChaCha20 Stream Cipher

### Usage

```bash
./chacha20.py <keyfilename> <NONCE> <inputfilename> <outputfilename>
```

### Parameters

- **keyfilename**: Path to a file containing a 32-byte key (as binary data, not hex-encoded)
- **NONCE**: 12-byte nonce as a 24-character hexadecimal string
- **inputfilename**: Path to the input file (binary data)
- **outputfilename**: Path to the output file (binary data)

### Description

ChaCha20 is a stream cipher that uses the same algorithm for both encryption and decryption. The cipher:
1. Takes a 256-bit key, a 96-bit nonce, and a 32-bit counter
2. Generates a keystream using the ChaCha20 block function
3. XORs the keystream with the plaintext/ciphertext

The implementation follows RFC 8439:
- **Quarter Round Function** (Section 2.1): The basic building block
- **State Operations** (Section 2.2): Quarter rounds applied to the 4x4 state matrix
- **ChaCha20 Block Function** (Section 2.3): 20 rounds (10 iterations of double rounds)
- **ChaCha20 Encryption** (Section 2.4): Stream cipher using the block function

### Test Vector (RFC 8439 Section 2.4.2)

**Key**: `00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f`

**Nonce**: `00:00:00:00:00:00:00:4a:00:00:00:00`

**Counter**: `1`

**Plaintext** (sunscreen.txt):
```
Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.
```

**Expected Ciphertext**:
```
6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81
e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b
f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57
16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8
07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e
52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36
5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42
87 4d
```

### Examples

Encrypt the sunscreen text:
```bash
./chacha20.py keyfile 000000000000004a00000000 sunscreen.txt ciphertext.bin
```

Decrypt the ciphertext:
```bash
./chacha20.py keyfile 000000000000004a00000000 ciphertext.bin decrypted.txt
```

## Part 2: ChaCha20-Poly1305 AEAD

### aead_wrap - Authenticated Encryption

Encrypts plaintext and authenticates both the associated data and ciphertext.

#### Usage

```bash
./aead_wrap.py <keyfilename> <NONCE> <adfilename> <plaintextfilename> <ciphertextfilename>
```

#### Parameters

- **keyfilename**: Path to a file containing a 32-byte key (binary)
- **NONCE**: 12-byte nonce as a 24-character hexadecimal string
- **adfilename**: Path to file containing associated data (authenticated but not encrypted)
- **plaintextfilename**: Path to the plaintext file
- **ciphertextfilename**: Path to write the ciphertext

#### Output

Writes the ciphertext to the specified file and prints the 128-bit authentication tag (hex-encoded) to standard output.


### aead_unwrap - Authenticated Decryption

Verifies the authentication tag and decrypts the ciphertext if valid.

#### Usage

```bash
./aead_unwrap.py <keyfilename> <NONCE> <adfilename> <ciphertextfilename> <TAG>
```

#### Parameters

- **keyfilename**: Path to a file containing a 32-byte key (binary)
- **NONCE**: 12-byte nonce as a 24-character hexadecimal string
- **adfilename**: Path to file containing associated data
- **ciphertextfilename**: Path to the ciphertext file
- **TAG**: 128-bit authentication tag as a 32-character hexadecimal string

#### Output

- If tag is **valid**: Prints the decrypted plaintext to standard output
- If tag is **invalid**: Exits silently without output

### AEAD Test Vector (RFC 8439 Section 2.8.2)

**Key**: `80:81:82:83:84:85:86:87:88:89:8a:8b:8c:8d:8e:8f:90:91:92:93:94:95:96:97:98:99:9a:9b:9c:9d:9e:9f`

**Nonce**: `07:00:00:00:40:41:42:43:44:45:46:47`

**Associated Data**: `50:51:52:53:c0:c1:c2:c3:c4:c5:c6:c7`

**Plaintext**: Same as ChaCha20 test (sunscreen text)

**Expected Tag**: `1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91`

### Examples

Wrap (encrypt and authenticate):
```bash
./aead_wrap.py keyfile 070000004041424344454647 aad sunscreen.txt my_ciphertext.bin
# Outputs tag: 1ae10b594f09e26a7e902ecbd0600691
```

Unwrap (verify and decrypt):
```bash
./aead_unwrap.py keyfile 070000004041424344454647 aad my_ciphertext.bin 1ae10b594f09e26a7e902ecbd0600691
# Outputs: Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.
```

Invalid tag example:
```bash
./aead_unwrap.py keyfile 070000004041424344454647 aad my_ciphertext.bin 0000000000000000000000000000000
# No output - exits silently due to invalid tag
```

## Testing

To verify your implementation matches RFC 8439:

1. **ChaCha20 Test**:
   ```bash
   # Encrypt
   ./chacha20.py keyfile 000000000000004a00000000 sunscreen.txt my_cipher.bin
   # Compare with expected ciphertext
   diff my_cipher.bin ciphertext.bin
   
   # Decrypt
   ./chacha20.py keyfile 000000000000004a00000000 my_cipher.bin my_plain.txt
   # Compare with original
   diff my_plain.txt sunscreen.txt
   ```

2. **AEAD Test**:
   ```bash
   # Wrap
   ./aead_wrap.py key_for_wrap 070000004041424344454647 aad sunscreen.txt test_cipher.bin
   # Should output: 1ae10b594f09e26a7e902ecbd0600691
   
   # Unwrap with correct tag
   ./aead_unwrap.py key_for_wrap 070000004041424344454647 aad test_cipher.bin 1ae10b594f09e26a7e902ecbd0600691
   # Should output the sunscreen text
   
   # Unwrap with incorrect tag
   ./aead_unwrap.py key_for_wrap 070000004041424344454647 aad test_cipher.bin 0000000000000000000000000000000
   # Should produce no output
   ```

## Author

Thomas Fargues