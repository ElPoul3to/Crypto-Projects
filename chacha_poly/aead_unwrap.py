#!/usr/bin/env python3
import sys
from chacha20 import chacha20_block, chacha20_encrypt
import importlib
poly1305_gen = importlib.import_module("poly1305-gen")
poly1305_mac = poly1305_gen.poly1305_mac

# --- Utility functions --- #
def hex_to_list(h: str) -> list:
    return list(bytes.fromhex(h))


def list_to_hex(l: list) -> str:
    return bytes(l).hex()


def read_file(filename: str) -> list:
    with open(filename, "rb") as f:
        content = f.read()
    return list(content)


def pad16(x: list) -> list:
    if len(x) % 16 == 0:
        return []
    else:
        pad_len = 16 - (len(x) % 16)
        return [0] * pad_len


def num_to_8_le_bytes(n: int) -> list:
    return list(n.to_bytes(8, "little"))


# --- aead_wrap functions --- #
def poly1305_key_gen(key: list, nonce: list) -> list:
    counter = 0
    block = chacha20_block(key, counter, nonce)
    return block[:32]

def chacha20_aead_decrypt(key:list, nonce:list, aad:list, ciphertext:list, tag:str) -> list:
    otk = poly1305_key_gen(key, nonce)
    mac_data = (
        aad
        + pad16(aad)
        + ciphertext
        + pad16(ciphertext)
        + num_to_8_le_bytes(len(aad))
        + num_to_8_le_bytes(len(ciphertext))
    )
    computed_tag = poly1305_mac(mac_data, otk)
    if computed_tag != tag:
        print("Tag mismatch! Decryption failed.")
        sys.exit(1)
    plaintext = chacha20_encrypt(key, 1, nonce, ciphertext)
    return plaintext


# --- Main --- #
if __name__ == "__main__":
    args = sys.argv
    if len(args) != 6:
        print("Error: incorrect number of arguments")
        sys.exit(1)
    else:
        keyfilename = args[1]
        nonce_hex = args[2]
        adfilename = args[3]
        ciphertextfilename = args[4]
        tag = args[5]
        
        key_list = read_file(keyfilename)
        nonce_list = hex_to_list(nonce_hex)
        aad_list = read_file(adfilename)
        ciphertext_list = read_file(ciphertextfilename)
        
        
        plaintext_list = chacha20_aead_decrypt(
            key_list, nonce_list, aad_list, ciphertext_list, tag
        )
        
        print(bytes(plaintext_list).decode('utf-8', errors='ignore'))