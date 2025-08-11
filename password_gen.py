

import argparse
import string
import secrets
import math
import sys
import time
from typing import List

AMBIGUOUS = {'l', 'I', '1', 'O', '0'}

def build_charset(use_lower, use_upper, use_digits, use_symbols, avoid_ambiguous):
    chars = []
    if use_lower:
        chars += list(string.ascii_lowercase)
    if use_upper:
        chars += list(string.ascii_uppercase)
    if use_digits:
        chars += list(string.digits)
    if use_symbols:
        chars += list("!@#$%&*()-_=+[]{};:,.<>?/")
    if avoid_ambiguous:
        chars = [c for c in chars if c not in AMBIGUOUS]
    if not chars:
        raise ValueError("Empty charset: enable at least one category.")
    return chars

def generate_password(length: int, charset: List[str]) -> str:
    return ''.join(secrets.choice(charset) for _ in range(length))

def compute_entropy(length: int, charset_size: int) -> float:
    return length * (math.log(charset_size, 2))

def compute_length_for_entropy(entropy: float, charset_size: int) -> int:
    return math.ceil(entropy / math.log(charset_size, 2))

def main():
    p = argparse.ArgumentParser(description="Secure Password Generator (by desired entropy)")
    p.add_argument("--entropy", "-e", type=float, default=80, help="Desired password strength in bits (default: 80)")
    p.add_argument("--no-upper", action="store_true", help="Disable uppercase")
    p.add_argument("--no-lower", action="store_true", help="Disable lowercase")
    p.add_argument("--no-digits", action="store_true", help="Disable digits")
    p.add_argument("--no-symbols", action="store_true", help="Disable symbols")
    p.add_argument("--no-ambiguous", action="store_true", help="Avoid ambiguous chars (0,O,1,l,I)")
    p.add_argument("--count", "-n", type=int, default=1, help="How many passwords to generate")
    args = p.parse_args()

    use_lower = not args.no_lower
    use_upper = not args.no_upper
    use_digits = not args.no_digits
    use_symbols = not args.no_symbols

    try:
        charset = build_charset(use_lower, use_upper, use_digits, use_symbols, args.no_ambiguous)
    except ValueError as e:
        print("Error:", e)
        sys.exit(1)

    size = len(charset)
    length = compute_length_for_entropy(args.entropy, size)
    actual_entropy = compute_entropy(length, size)

    print(f"Charset size: {size}")
    print(f"Target entropy: {args.entropy} bits")
    print(f"Calculated length: {length}")
    print(f"Actual entropy: {actual_entropy:.2f} bits\n")

    for i in range(args.count):
        pw = generate_password(length, charset)
        print(pw)

    time.sleep(0.1)

if __name__ == "__main__":
    main()


