#!/usr/bin/env python3
import sys


# --- Global constants (Pre-calculated according to FIPS 202) --- #
RATE_BYTES = 168

RC = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
]


RHO_OFFSETS = [
    0,
    1,
    62,
    28,
    27,
    36,
    44,
    6,
    55,
    20,
    3,
    10,
    43,
    25,
    39,
    41,
    45,
    15,
    21,
    8,
    18,
    2,
    61,
    56,
    14,
]

# Permutation table for Pi: new_index = PI[old_index]
PI_INDICES = [
    0,
    6,
    12,
    18,
    24,
    3,
    9,
    10,
    16,
    22,
    1,
    7,
    13,
    19,
    20,
    4,
    5,
    11,
    17,
    23,
    2,
    8,
    14,
    15,
    21,
]

# --- Utility functions --- #


# From https://github.com/samgh/Byte-by-Byte-Solutions/blob/master/python/RotateBits.py
def rol64(a, n):
    """Left rotation on 64 bits."""
    return ((a << n) | (a >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def byte_to_array(b_data):
    """Converts a byte sequence into a list of 25 integers (little-endian)."""
    state = [0] * 25
    for i in range(0, len(b_data), 8):
        if i + 8 <= len(b_data):
            state[i // 8] = int.from_bytes(b_data[i : i + 8], "little")
        else:
            # Rare case where we convert a partial remainder (potentially used for display)
            padding = b_data[i:] + b"\x00" * (8 - len(b_data[i:]))
            state[i // 8] = int.from_bytes(padding, "little")
    return state


def array_to_byte(state):
    """Converts the state (25 integers) into a bytes object."""
    b_data = bytearray()
    for lane in state:
        b_data.extend(lane.to_bytes(8, "little"))
    return bytes(b_data)


def print_state(state):
    """Displays the state in hexadecimal format (debug)."""
    print(array_to_byte(state).hex())


def apply_padding(remaining_data, block_size):
    """
    Applies SHAKE128 padding (suffix 1111 + pad10*1).
    """
    padding_block = bytearray(remaining_data) + bytearray(
        block_size - len(remaining_data)
    )
    padding_block[len(remaining_data)] ^= 0x1F
    padding_block[block_size - 1] ^= 0x80

    return padding_block


# --- The 5 steps of the permutation (Theta, Rho, Pi, Chi, Iota) --- #


def theta(A):
    C = [0] * 5
    D = [0] * 5
    for x in range(5):
        C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20]

    for x in range(5):
        D[x] = C[(x - 1) % 5] ^ rol64(C[(x + 1) % 5], 1)

    for i in range(25):
        A[i] ^= D[i % 5]
    return A


def rho(A):
    for i in range(25):
        A[i] = rol64(A[i], RHO_OFFSETS[i])
    return A


def pi(A):
    new_A = [0] * 25
    for i in range(25):
        new_A[i] = A[PI_INDICES[i]]
    return new_A


def chi(A):
    new_A = [0] * 25
    for y in range(0, 25, 5):
        for x in range(5):
            new_A[y + x] = A[y + x] ^ ((~A[y + (x + 1) % 5]) & A[y + (x + 2) % 5])
    return new_A


def iota(A, round_idx):
    A[0] ^= RC[round_idx]
    return A


def keccak_f1600(state):
    """Executes the 24 rounds of the permutation."""
    for i_r in range(24):
        state = theta(state)
        state = rho(state)
        state = pi(state)
        state = chi(state)
        state = iota(state, i_r)
    return state


# --- Sponge function --- #


def shake128_sponge(input_bytes, output_len):
    block_size = RATE_BYTES
    state = [0] * 25

    # Absorbing
    offset = 0
    while offset + block_size <= len(input_bytes):
        block = input_bytes[offset : offset + block_size]
        block_lanes = byte_to_array(block)
        for i in range(len(block_lanes)):
            state[i] ^= block_lanes[i]

        state = keccak_f1600(state)
        offset += block_size

    # last block with padding
    remaining = input_bytes[offset:]
    padding_block = apply_padding(remaining, block_size)

    pad_lanes = byte_to_array(padding_block)
    for i in range(len(pad_lanes)):
        state[i] ^= pad_lanes[i]

    state = keccak_f1600(state)

    # Squeezing
    output_bytes = bytearray()
    while len(output_bytes) < output_len:
        # Extract rate part from state
        state_as_bytes = array_to_byte(state)
        bytes_to_take = min(output_len - len(output_bytes), block_size)

        output_bytes.extend(state_as_bytes[:bytes_to_take])

        if len(output_bytes) < output_len:
            state = keccak_f1600(state)

    return output_bytes


# --- Main --- #

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <nb_bytes>")
        sys.exit(1)

    try:
        req_bytes = int(sys.argv[1])
    except ValueError:
        print("Error: number of bytes must be an integer")
        sys.exit(1)

    try:
        input_data = sys.stdin.buffer.read()
    except AttributeError:
        input_data = sys.stdin.read().encode("utf-8")

    digest = shake128_sponge(input_data, req_bytes)

    print(digest.hex())
