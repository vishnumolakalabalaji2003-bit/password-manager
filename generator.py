"""
Random password / passphrase generator.

- generate_password(): a strong random password with configurable
  length and character classes (upper, lower, digits, symbols).
- generate_passphrase(): a multi-word passphrase built from an
  uncommon word list, which is easier for humans to remember while
  still resisting brute-force and dictionary attacks (given enough
  words), matching the approach described in the original project
  report.
"""
import secrets
import string

WORDLIST = [
    "orbit", "flannel", "cobalt", "ember", "marble", "thistle", "quartz",
    "lantern", "cinder", "willow", "granite", "meadow", "falcon", "cipher",
    "tundra", "velvet", "harbor", "onyx", "prairie", "zephyr", "birch",
    "canyon", "delta", "ember", "frost", "glacier", "haven", "ivory",
    "jasper", "kestrel", "lagoon", "monsoon", "nebula", "opal", "pinnacle",
]


def generate_password(length: int = 16, use_symbols: bool = True,
                       use_digits: bool = True, use_upper: bool = True) -> str:
    if length < 8:
        raise ValueError("Password length should be at least 8 characters.")

    pools = [string.ascii_lowercase]
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append("!@#$%^&*()-_=+[]{}")

    all_chars = "".join(pools)

    # Guarantee at least one character from each selected pool
    password_chars = [secrets.choice(pool) for pool in pools]
    password_chars += [secrets.choice(all_chars) for _ in range(length - len(pools))]
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


def generate_passphrase(num_words: int = 4, separator: str = "-", add_number: bool = True) -> str:
    words = [secrets.choice(WORDLIST) for _ in range(num_words)]
    phrase = separator.join(words)
    if add_number:
        phrase += separator + str(secrets.randbelow(100))
    return phrase


if __name__ == "__main__":
    print("Random password:  ", generate_password())
    print("Random passphrase:", generate_passphrase())
