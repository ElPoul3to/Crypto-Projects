# X25519 Implementation

## Overview

This is an implementation of the X25519 key agreement scheme according to [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748).

The implementation uses the Montgomery ladder algorithm for constant-time scalar multiplication on Curve25519, which helps protect against timing attacks.

## Requirements

- Python 3.x
- No external dependencies (uses only Python standard library)

## Installation

Make sure the script is executable:

```bash
chmod +x x25519.py
```

## Usage

```bash
./x25519.py <scalar_hex> [u_coord_hex]
```

### Parameters

- `scalar_hex`: A 32-byte scalar value in hexadecimal (64 hex characters)
- `u_coord_hex`: (Optional) A 32-byte u-coordinate in hexadecimal (64 hex characters). If omitted, uses the base point (u=9)

### Input/Output

- **Input**: Two hexadecimal strings representing the scalar and u-coordinate (both 32 bytes)
- **Output**: The resulting u-coordinate of the scalar multiplication in hexadecimal (32 bytes, little-endian)


## Examples

### Test Vectors from RFC 7748 (Section 5.2)

#### Test Vector 1
```bash
./x25519.py a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4 \
            e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c
```
**Expected output:**
```
c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552
```

#### Test Vector 2 (Scalar multiplication with base point)
```bash
./x25519.py 4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493
```
**Expected output:**
```
95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957
```

### Test Vectors from RFC 7748 (Section 6.1)
#### Test Vector 3 (Input: Alice's private key, a - Output: Alice's public key, X25519(a, 9))
```bash
./x25519.py 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
```
**Expected output:**
```
8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
```

#### Test Vector 4 (Input: Bob's private key, b - Output: Bob's public key, X25519(b, 9))
```bash
./x25519.py 5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
```
**Expected output:**
```
de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
```


#### Test Vector 5 (Shared key K = X25519(a, X25519(b, 9)) = X25519(b, X25519(a, 9)))
```bash
./x25519.py 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
./x25519.py 5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
```
**Expected output:**
```
4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
```



## Author

Thomas Fargues