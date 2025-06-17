# endectools/cli.py

import shutil, getpass, click
from pathlib import Path
from .core import encrypt_path, decrypt_path, shred_path
from . import __version__

@click.group(help="EndecTools – local file & directory encryption utilities.")
def cli():
    pass

# --- ENCRYPT COMMAND ---
@cli.command(name="encrypt", short_help="Encrypt a file or folder")
@click.argument("path", type=click.Path(exists=True, file_okay=True, dir_okay=True, path_type=Path))
@click.option("--out", "out_path", type=click.Path(path_type=Path), help="Output file name")
@click.option("-k", "--keep-source", is_flag=True, help="Preserve source (no delete/shred)")
@click.option("-n", "--no-shred", is_flag=True, help="Fast delete; skip secure erase")
def encrypt(path: Path, out_path: Path | None, keep_source: bool, no_shred: bool):
    """Encrypt a file or folder using streaming-only pipeline."""
    out_path = out_path or path.parent / f"{path.name}.enc"
    pwd = getpass.getpass("Pass-phrase: ").encode()
    encrypt_path(path, out_path, pwd)
    click.secho(f"Encrypted ➜ {out_path}", fg="green")
    if not keep_source:
        if no_shred:
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
            click.secho(f"Deleted source (fast) ➜ {path}", fg="yellow")
        else:
            click.secho("Securely shredding source…", fg="yellow")
            shred_path(path)
            click.secho(f"Shredded source ➜ {path}", fg="yellow")

# --- DECRYPT COMMAND ---
@cli.command(name="decrypt", short_help="Decrypt an encrypted archive")
@click.argument("path", type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path))
@click.option("--out", "out_path", type=click.Path(path_type=Path), help="Output folder")
@click.option("-k", "--keep-source", is_flag=True, help="Preserve archive (no delete/shred)")
@click.option("-n", "--no-shred", is_flag=True, help="Fast delete; skip secure erase")
def decrypt(path: Path, out_path: Path | None, keep_source: bool, no_shred: bool):
    """Decrypt an encrypted archive using streaming-only pipeline."""
    out_path = out_path or path.parent / path.stem
    pwd = getpass.getpass("Pass-phrase: ").encode()
    decrypt_path(path, out_path, pwd)
    click.secho(f"Decrypted ➜ {out_path}", fg="green")
    if not keep_source:
        if no_shred:
            path.unlink()
            click.secho(f"Deleted archive (fast) ➜ {path}", fg="yellow")
        else:
            click.secho("Securely shredding archive…", fg="yellow")
            shred_path(path)
            click.secho(f"Shredded archive ➜ {path}", fg="yellow")

# --- SHRED COMMAND ---
@cli.command(name="shred", short_help="Securely erase a file or directory")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("-p", "--passes", default=3, show_default=True, help="Overwrite passes")
@click.option("--pattern", type=click.Choice(["rand", "zero"]), default="rand", show_default=True)
def shred(path: Path, passes: int, pattern: str):
    """Securely erase a file or directory by overwriting data."""
    click.secho(f"Shredding {path} ({passes} passes, pattern={pattern})…", fg="yellow")
    shred_path(path, passes=passes, pattern=pattern)
    click.secho("Shred complete.", fg="green")

# --- VAULT COMMAND GROUP ---
@cli.group()
def vault():
    """Manage encrypted secrets vault."""
    pass

@vault.command()
def init():
    """Initialize a new encrypted vault."""
    from .vault import init_vault
    init_vault()

@vault.command()
def add():
    """Add a new secret to the vault."""
    from .vault import add_secret
    add_secret()

@vault.command()
def get():
    """Retrieve a secret from the vault."""
    from .vault import get_secret
    get_secret()

@vault.command()
def list():
    """List stored secret labels."""
    from .vault import list_secrets
    list_secrets()

@vault.command()
def edit():
    """Edit a stored secret in the vault."""
    from .vault import edit_secret
    edit_secret()

@vault.command()
def delete():
    """Delete a stored secret from the vault."""
    from .vault import delete_secret
    delete_secret()

@vault.command()
def destroy():
    """Permanently destroy the entire vault."""
    from .vault import delete_vault
    delete_vault()

# --- HASH COMMAND GROUP ---
@cli.group()
def hash():
    """Hashing utilities."""
    pass

@hash.command()
def string():
    """Hash a string with selectable algorithms."""
    from .utils.hashutils import hash_string_interactive
    hash_string_interactive()

# --- VERSION COMMAND ---
@cli.command()
def version():
    """Show EndecTools version."""
    click.echo(f"EndecTools {__version__}")

if __name__ == '__main__':
    cli()