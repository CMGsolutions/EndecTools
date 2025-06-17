import hashlib
from getpass import getpass

ALGOS = {
    "1": ("SHA-256", hashlib.sha256),
    "2": ("SHA-512", hashlib.sha512),
    "3": ("SHA3-256", hashlib.sha3_256),
    "4": ("BLAKE2b", hashlib.blake2b),
}

def hash_string_interactive():
    print("Enter string to hash:")
    s = getpass("Input: ")  # Using getpass to avoid showing input

    print("\nChoose algorithm:")
    for key, (name, _) in ALGOS.items():
        print(f"[{key}] {name}")

    choice = input("Select [1–4]: ").strip()
    algo = ALGOS.get(choice)

    if not algo:
        print("Invalid selection.")
        return

    name, func = algo
    digest = func(s.encode()).hexdigest()

    print(f"\n{name} Hash:")
    print(digest)
    print()