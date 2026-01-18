#!/usr/bin/env python3
import sys


# --- Utility functions --- #
def hex_to_list(h: str) -> list:
    return list(bytes.fromhex(h))


def list_to_hex(l: list) -> str:
    return bytes(l).hex()


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
    r_list = key[:16]
    s_list = key[16:]

    # Clamp r and convert also s to integer
    r_int = clamp(r_list)
    s_int = int.from_bytes(bytes(s_list), "little")

    # print(f"r (clamped) = {r_int.to_bytes(16, 'big').hex()}")
    # print(f"s = {list_to_hex(s_list)}")

    acc = 0
    p = (1 << 130) - 5  # 2^130 - 5

    for i in range(0, len(m), 16):
        block = m[i : i + 16]
        # print(f"\nBlock {i//16}:\n{bytes(block[::-1]).hex()}")

        # Add the 0x01 byte to the end of the block
        # (This handles the "Add 2^128" or "2^(n*8)" logic automatically)
        block.append(0x01)
        # print(f"Block with 0x01 byte = {bytes(block[::-1]).hex()}")

        n = int.from_bytes(bytes(block), "little")
        acc += n
        # print(f"Acc + block = {acc.to_bytes((acc.bit_length() + 7) // 8, 'big').hex()}")
        acc = (acc * r_int) % p
        # print(f"Block {i//16}: n = {n}, acc = {acc}")

    acc += s_int
    tag_int = acc % (1 << 128)  # Final reduction to 128 bits
    return tag_int.to_bytes(16, "little").hex()


# --- Main --- #
if __name__ == "__main__":
    args = sys.argv
    if len(args) != 3:
        print("Error: incorrect number of arguments")
        print("Usage: ./poly1305-gen <64-char-hex-key> <filename>")
        sys.exit(1)
    else:
        try:
            key_str = args[1]
            filename = args[2]

            if len(key_str) != 64:
                raise ValueError("Key must be 64 hex characters (32 bytes)")

            key = hex_to_list(key_str)
            m = read_file(filename)

            print(poly1305(key, m))

        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)


"""
Test:

key = 85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b

r = 85d6be7857556d337f4452fe42d506a8

s = 0103808afb0db2fd4abff6af4149f51b


clamp(r) = 0806d5400e52447c036d555408bed685


Block #1


Acc = 00

Block = 6f4620636968706172676f7470797243

Block with 0x01 byte = 016f4620636968706172676f7470797243

Acc + block = 016f4620636968706172676f7470797243

(Acc+Block) * r =

b83fe991ca66800489155dcd69e8426ba2779453994ac90ed284034da565ecf

Acc = ((Acc+Block)*r) % P = 2c88c77849d64ae9147ddeb88e69c83fc


Block #2


Acc = 2c88c77849d64ae9147ddeb88e69c83fc

Block = 6f7247206863726165736552206d7572

Block with 0x01 byte = 016f7247206863726165736552206d7572

Acc + block = 437febea505c820f2ad5150db0709f96e

(Acc+Block) * r =

21dcc992d0c659ba4036f65bb7f88562ae59b32c2b3b8f7efc8b00f78e548a26

Acc = ((Acc+Block)*r) % P = 2d8adaf23b0337fa7cccfb4ea344b30de

Last Block


Acc = 2d8adaf23b0337fa7cccfb4ea344b30de

Block = 7075

Block with 0x01 byte = 017075

Acc + block = 2d8adaf23b0337fa7cccfb4ea344ca153

(Acc + Block) * r =

16d8e08a0f3fe1de4fe4a15486aca7a270a29f1e6c849221e4a6798b8e45321f

((Acc + Block) * r) % P = 28d31b7caff946c77c8844335369d03a7


Adding s, we get this number, and serialize if to get the tag:


Acc + s = 2a927010caf8b2bc2c6365130c11d06a8


Tag: a8061dc1305136c6c22b8baf0c0127a9
"""
