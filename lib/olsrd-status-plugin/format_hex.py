#!/usr/bin/env python3
"""
UBNT Hex Dump Formatter
Converts hexdump output to C array format for UBNT_DISCOVER_TEST
Usage: python3 format_hex.py <input_file>
"""

import sys
import re

def format_hex_dump(input_file):
    """Convert hexdump output to C array format"""
    hex_bytes = []

    with open(input_file, 'r') as f:
        for line in f:
            # Look for hexdump lines (format: "0000  xx xx xx xx ...")
            match = re.match(r'([0-9a-f]{4})\s+((?:[0-9a-f]{2}\s+)+)', line)
            if match:
                # Extract hex bytes from the line
                hex_values = match.group(2).strip().split()
                hex_bytes.extend([f'0x{b}' for b in hex_values])

    if not hex_bytes:
        print("No hexdump data found in input file")
        return

    # Format as C array
    print("/* UBNT discovery response dump */")
    print("const uint8_t buf[] = {")

    # Print in rows of 16 bytes
    for i in range(0, len(hex_bytes), 16):
        row = hex_bytes[i:i+16]
        print("    " + ",".join(row) + ("," if i + 16 < len(hex_bytes) else ""))

    print("};")
    print(f"size_t len = sizeof(buf); /* {len(hex_bytes)} bytes */")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 format_hex.py <input_file>")
        sys.exit(1)

    format_hex_dump(sys.argv[1])