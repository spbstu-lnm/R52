#!/usr/bin/env python3

import argparse

MASK64 = 0xFFFFFFFFFFFFFFFF
INITIAL_STATE = 0xB7E151628AED2A6A


def rol64(value: int, count: int) -> int:
    """64-bit rotate left."""
    count %= 64
    if count == 0:
        return value & MASK64

    return ((value << count) | (value >> (64 - count))) & MASK64


def generate_serial(name: str) -> str:
    # GetDlgItemTextA gets string in ANSI encoding.
    # For the given examples, ASCII is sufficient.
    try:
        data = name.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(
            "Use ASCII-name or encode it "
            "in the same ANSI encoding that the Windows program uses."
        ) from exc

    if not data:
        raise ValueError("Name cannot be empty.")

    if len(data) > 249:
        raise ValueError("Name exceeds the size of the allowed input buffer.")

    # first field: length of the name.
    length_field = f"{len(data):02X}"

    # second field: sum of the number of set bits.
    checksum = sum(byte.bit_count() for byte in data) & 0xFF
    checksum_field = f"{checksum:02X}"

    # last field: 64-bit func with name as input
    state = INITIAL_STATE

    for byte in data:
        n = byte.bit_count()

        state = rol64(state, n)

        if n & 1:
            byte ^= 0xFF

        state ^= byte
        state &= MASK64

    return f"{length_field}{checksum_field}-{state:016X}"


def main():
    parser = argparse.ArgumentParser(
        description="Static key generator for the VM crackme"
    )
    parser.add_argument("name", help="Name entered into the crackme")
    args = parser.parse_args()

    print(f"Name   : {args.name}")
    print(f"Serial : {generate_serial(args.name)}")


if __name__ == "__main__":
    main()
