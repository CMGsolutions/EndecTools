# endectools/utils/hashutils.py

import hashlib
import click

def hash_string(s: str, algorithm: str = "sha256") -> str:
    """
    Hash a string using the specified algorithm and return the hex digest.
    """
    h = hashlib.new(algorithm)
    h.update(s.encode("utf-8"))
    return h.hexdigest()

def hash_string_interactive() -> str:
    """
    Prompt the user for a string and hashing algorithm, then output the hash.
    """
    s = click.prompt("Enter string to hash", type=str)

    click.echo("\nChoose algorithm:")
    click.echo("[1] SHA-256")
    click.echo("[2] SHA-512")
    click.echo("[3] SHA3-256")
    click.echo("[4] BLAKE2b")
    selection = click.prompt("Selection", type=int, default=1)

    algorithm = {
        1: "sha256",
        2: "sha512",
        3: "sha3_256",
        4: "blake2b"
    }.get(selection)

    if algorithm is None:
        click.secho("Invalid selection.", fg="red")
        return None

    digest = hash_string(s, algorithm)
    click.secho(f"{algorithm.upper()} → {digest}", fg="green")
    return digest