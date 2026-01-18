# Poly1305 Function Implementation

## Overview

This project implements the Poly1305 message authentication code (MAC) algorithm, a cryptographic one-time authenticator. Poly1305 generates a 128-bit authentication tag for a message using a 256-bit one-time key.

The implementation provides a command-line tool that computes the Poly1305 MAC tag for any file using a provided 256-bit key.

## Requirements

- Python 3.x
- No external dependencies (uses only Python standard library)

## Installation

Make sure the script is executable:

```bash
chmod u+x poly1305-gen.py
chmod u+x poly1305-check.py
```

## Usage

### Generating a MAC Tag

```bash
./poly1305-gen.py <64-char-hex-key> <filename>
```

Computes and outputs the Poly1305 authentication tag for the given file.

### Verifying a MAC Tag

```bash
./poly1305-check.py <64-char-hex-key> <filename> <tag>
```

Verifies if a given tag is valid for the file. Outputs `ACCEPT` if the tag is correct, `REJECT` otherwise.

### Parameters

- `<64-char-hex-key>`: A 256-bit key represented as 64 hexadecimal characters (32 bytes)
  - First 16 bytes (32 hex chars) are used for `r` (clamped during processing)
  - Last 16 bytes (32 hex chars) are used for `s`
- `<filename>`: Path to the file to authenticate
- `<tag>`: Expected 128-bit authentication tag in hexadecimal format (32 characters, only for poly1305-check.py)

### Input/Output

#### poly1305-gen
- **Input**: 
  - A 256-bit key in hexadecimal format (64 characters)
  - A file containing the message to authenticate
- **Output**: 
  - A 128-bit authentication tag in hexadecimal format (32 characters)

#### poly1305-check
- **Input**: 
  - A 256-bit key in hexadecimal format (64 characters)
  - A file
  - A 128-bit tag in hexadecimal format (32 characters)
- **Output**: 
  - If the tag is ACCEPT or REJECT for the corresponding file

## Examples

### Example 1: Generating a MAC tag

```bash
./poly1305-gen.py 85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b file
```

**Output:**
```
a8061dc1305136c6c22b8baf0c0127a9
```

This computes the Poly1305 MAC tag for the file `file` using the provided key.

### Example 2: Verifying a MAC tag

```bash
./poly1305-check.py 85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b file a8061dc1305136c6c22b8baf0c0127a9
```

**Output:**
```
ACCEPT
```

This verifies that the provided tag is valid for the message.

### Example 3: Verifying with an incorrect tag

```bash
./poly1305-check.py 85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b file 0000000000000000000000000000000
```

**Output:**
```
REJECT
```

## Author

Thomas Fargues