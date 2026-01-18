#!/usr/bin/env python3
import sys


# --- Utility functions --- #
def hex_to_list(h: str) -> list:
    return list(bytes.fromhex(h))


def read_file(filename: str) -> list:
    with open(filename, "rb") as f:
        content = f.read()
    return list(content)


# --- poly1305 functions --- #
def clamp(r: list) -> int:
    r[3] &= 15
    r[7] &= 15
    r[11] &= 15
    r[15] &= 15
    r[4] &= 252
    r[8] &= 252
    r[12] &= 252
    return int.from_bytes(bytes(r), "little")


def poly1305(key: list, m: list) -> str:
    r_int = clamp(key[:16])
    s_int = int.from_bytes(bytes(key[16:]), "little")
    acc = 0
    p = (1 << 130) - 5

    for i in range(0, len(m), 16):
        block = m[i : i + 16]
        block.append(0x01)
        n = int.from_bytes(bytes(block), "little")
        acc = (acc + n) * r_int % p

    acc += s_int
    tag_int = acc % (1 << 128)
    return tag_int.to_bytes(16, "little").hex()


# --- Main --- #
if __name__ == "__main__":
    args = sys.argv
    if len(args) != 4:
        print("Error: incorrect number of arguments")
        print("Usage: ./poly1305-check <key> <filename> <tag>")
        sys.exit(1)

    try:
        key_str = args[1]
        filename = args[2]
        expected_tag = args[3].lower()

        if len(key_str) != 64:
            raise ValueError("Key must be 64 hex characters")

        key = hex_to_list(key_str)
        m = read_file(filename)

        computed_tag = poly1305(key, m)

        if computed_tag == expected_tag:
            print("ACCEPT")
        else:
            print("REJECT")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
