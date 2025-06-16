import shutil
import getpass
from pathlib import Path
import click
from .core import encrypt_path, decrypt_path
from . import __version__

@click.group(context_settings=dict(help_option_names=["-h", "--help"]),
             help="EndecTools – local file & directory encryption utilities.")
def cli() -> None:
    pass

@cli.command()
def version() -> None:
    """Show EndecTools version."""
    click.echo(f"EndecTools {__version__}")

@cli.command()
@click.argument(
    "path",
    type=click.Path(exists=True, file_okay=True, dir_okay=True, path_type=Path),
)
@click.option(
    "--out", "out_path", type=click.Path(path_type=Path),
    help="Output file name (default: <parent>/<name>.enc)"
)
@click.option(
    "-k", "--keep-source", is_flag=True,
    help="Keep the original file/folder after encryption"
)
def encrypt(path: Path, out_path: Path | None, keep_source: bool) -> None:
    """
    Encrypt a file or folder (zip+encrypt).  
    By default deletes the source; pass --keep-source to preserve it.
    """
    out_path = out_path or path.parent / f"{path.name}.enc"
    if out_path.exists():
        click.echo("Error: output exists."); raise click.Abort()

    pwd = getpass.getpass("Pass-phrase: ").encode()
    encrypt_path(path, out_path, pwd)
    click.secho(f"Encrypted ➜ {out_path}", fg="green")

    if not keep_source:
        # Remove the original file or directory
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        click.secho(f"Deleted source ➜ {path}", fg="yellow")

@cli.command()
@click.argument(
    "path",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--out", "out_path", type=click.Path(path_type=Path),
    help="Output name (default: drops .enc, placed next to PATH)"
)
@click.option(
    "-k", "--keep-source", is_flag=True,
    help="Keep the .enc archive after decryption"
)
def decrypt(path: Path, out_path: Path | None, keep_source: bool) -> None:
    """
    Decrypt an archive created by `endec encrypt`.  
    By default deletes the .enc file; pass --keep-source to preserve it.
    """
    if out_path is None:
        # default to same parent, basename without .enc
        basename = path.stem if path.suffix == ".enc" else path.name
        out_path = path.parent / basename

    pwd = getpass.getpass("Pass-phrase: ").encode()
    try:
        decrypt_path(path, out_path, pwd)
    except ValueError as exc:
        click.secho(f"Error: {exc}", fg="red"); raise click.Abort()

    click.secho(f"Decrypted ➜ {out_path}", fg="green")

    if not keep_source:
        path.unlink()
        click.secho(f"Deleted encrypted ➜ {path}", fg="yellow")

if __name__ == "__main__":
    cli()