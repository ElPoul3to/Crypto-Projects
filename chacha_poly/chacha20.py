#!/usr/bin/env python3
import sys


# --- Global constants --- #
CHACHA20_CST = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]


# --- Utility functions --- #
def hex_to_list(h: str) -> list:
    return list(bytes.fromhex(h))


def list_to_hex(l: list) -> str:
    return bytes(l).hex()


def print_state(state):
    for i in range(4):
        print(
            f"{state[4*i]:08x} {state[4*i+1]:08x} {state[4*i+2]:08x} {state[4*i+3]:08x}"
        )


def read_file(filename: str) -> list:
    with open(filename, "rb") as f:
        content = f.read()
    return list(content)


def rotl32(value, amount):
    return ((value << amount) & 0xFFFFFFFF) | (value >> (32 - amount))


def serialize_state(state):
    output = []
    for word in state:
        output += list(word.to_bytes(4, "little"))
    return output


# --- chacha20 functions --- #
def quarter_round(state, a, b, c, d):
    # Additions are modulo 2^32 so we mask with 0xFFFFFFFF
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = rotl32(state[d], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = rotl32(state[b], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = rotl32(state[d], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = rotl32(state[b], 7)


def inner_block(state):
    quarter_round(state, 0, 4, 8, 12)
    quarter_round(state, 1, 5, 9, 13)
    quarter_round(state, 2, 6, 10, 14)
    quarter_round(state, 3, 7, 11, 15)
    quarter_round(state, 0, 5, 10, 15)
    quarter_round(state, 1, 6, 11, 12)
    quarter_round(state, 2, 7, 8, 13)
    quarter_round(state, 3, 4, 9, 14)


def chacha20_block(key: list, counter: int, nonce: list) -> list:
    state = CHACHA20_CST.copy()
    state += [int.from_bytes(bytes(key[i : i + 4]), "little") for i in range(0, 32, 4)]
    state.append(counter)
    state += [
        int.from_bytes(bytes(nonce[i : i + 4]), "little") for i in range(0, 12, 4)
    ]

    initial_state = state.copy()

    for i in range(10):
        inner_block(state)
    state = [(initial_state[i] + state[i]) & 0xFFFFFFFF for i in range(16)]

    return serialize_state(state)


def chacha20_encrypt(key: list, counter: int, nonce: list, plaintext: list) -> list:
    encrypted_message = []
    for j in range(len(plaintext) // 64):
        key_stream = chacha20_block(key, counter + j, nonce)
        block = plaintext[j * 64 : (j + 1) * 64]
        encrypted_message += [block[i] ^ key_stream[i] for i in range(len(block))]

    if len(plaintext) % 64 != 0:
        j = len(plaintext) // 64
        key_stream = chacha20_block(key, counter + j, nonce)
        block = plaintext[j * 64 : len(plaintext)]
        encrypted_message += [block[i] ^ key_stream[i] for i in range(len(block))][
            : len(plaintext) % 64
        ]

    return encrypted_message


# --- Main --- #
if __name__ == "__main__":
    args = sys.argv
    if len(args) != 5:
        print("Error: incorrect number of arguments")
        sys.exit(1)
    else:
        keyfile_bin = args[1]
        nonce_hex = args[2]
        input_file_bin = args[3]
        output_file_bin = args[4]
        
        key_list = read_file(keyfile_bin)
        nonce_list = hex_to_list(nonce_hex)
        plaintext = read_file(input_file_bin)
        encrypted_message = chacha20_encrypt(key_list, 1, nonce_list, plaintext)
        with open(output_file_bin, "wb") as f:
            f.write(bytes(encrypted_message))
        print(f"Encryption complete. Ciphertext written to {output_file_bin}")