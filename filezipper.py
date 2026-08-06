#!/usr/bin/env python3
"""Encrypt a file into an AES-encrypted ZIP archive, or decrypt one.

The command-line interface is intentionally small, while the file operations
are exposed as functions so they can also be tested or reused by another
program.
"""

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Iterable

try:
    import pyzipper
except ImportError:  # pragma: no cover - exercised by an installation error
    pyzipper = None  # type: ignore[assignment]


APP_NAME = "filezipper"
PASSWORD_ITERATIONS = 600_000
CHUNK_PATTERN = re.compile(r"^(?P<base>.+)\.part(?P<number>\d+)$")


def normalize_path(value: str | os.PathLike[str]) -> Path:
    """Return a Path from user input on Windows, macOS, and Linux.

    Users commonly paste paths surrounded by quotes, or paste a Windows path
    containing backslashes into a Unix terminal.  Removing a pair of outer
    quotes and normalizing both slash styles makes those inputs work without
    changing ordinary Path behavior elsewhere in the program.
    """

    text = os.fspath(value).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        text = text[1:-1].strip()

    text = os.path.expandvars(os.path.expanduser(text))

    # A path copied from a shell may escape a space as ``\\ ``.  That is an
    # escaped space, not a directory separator (for example,
    # ``Untitled\\ 1.wav``).  Decode it before converting the remaining
    # separator style.  This works on Windows too, where users sometimes
    # paste shell-style paths into the prompt.
    text = text.replace("\\ ", " ")
    if os.sep == "/":
        text = text.replace("\\", "/")
    else:
        text = text.replace("/", "\\")
    return Path(text)


# British spelling is kept as a convenient alias for callers using the
# wording in the prompt.
normalise_path = normalize_path


def megabytes_to_bytes(value: str) -> int:
    """Convert a positive decimal megabyte value to bytes.

    Decimal values are accepted (for example, ``0.5``).  A megabyte means
    1024 * 1024 bytes, which is also the convention used by the UI.
    """

    try:
        number = float(value.strip())
    except (AttributeError, ValueError):
        raise ValueError("Chunk size must be a positive number of megabytes") from None

    if not math.isfinite(number) or number <= 0:
        raise ValueError("Chunk size must be a positive number of megabytes")

    size = int(number * 1024 * 1024)
    if size <= 0:
        raise ValueError("Chunk size is too small")
    return size


def _require_pyzipper() -> None:
    if pyzipper is None:
        raise RuntimeError(
            "The 'pyzipper' package is not installed. Run: "
            f"{sys.executable} -m pip install -r requirements.txt"
        )


def _as_path(value: str | os.PathLike[str]) -> Path:
    return Path(value).expanduser()


def _ensure_directory(value: str | os.PathLike[str]) -> Path:
    directory = _as_path(value)
    directory.mkdir(parents=True, exist_ok=True)
    if not directory.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory}")
    return directory


def _archive_path(source: Path, destination: Path) -> Path:
    return destination / f"{source.name}.zip"


def split_file(file_path: str | os.PathLike[str], chunk_size: int) -> list[Path]:
    """Split *file_path* into numbered sibling files and remove the original.

    The generated names are ``<file_path>.part001``, ``.part002``, and so on.
    Existing output files are never overwritten.  If an error occurs, chunks
    created during this call are removed where possible.
    """

    path = _as_path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")
    if not isinstance(chunk_size, int) or isinstance(chunk_size, bool) or chunk_size <= 0:
        raise ValueError("Chunk size must be a positive integer number of bytes")

    total_size = path.stat().st_size
    number_of_chunks = max(1, math.ceil(total_size / chunk_size))
    width = max(3, len(str(number_of_chunks)))
    chunk_paths = [
        path.with_name(f"{path.name}.part{index:0{width}d}")
        for index in range(1, number_of_chunks + 1)
    ]

    existing = next((chunk for chunk in chunk_paths if chunk.exists()), None)
    if existing is not None:
        raise FileExistsError(f"Output already exists: {existing}")

    created: list[Path] = []
    try:
        with path.open("rb") as source:
            for chunk_path in chunk_paths:
                remaining = chunk_size
                with chunk_path.open("xb") as chunk:
                    created.append(chunk_path)
                    while remaining:
                        block = source.read(min(1024 * 1024, remaining))
                        if not block:
                            break
                        chunk.write(block)
                        remaining -= len(block)
    except Exception:
        for chunk_path in created:
            try:
                chunk_path.unlink()
            except OSError:
                pass
        raise

    try:
        path.unlink()
    except Exception:
        for chunk_path in created:
            try:
                chunk_path.unlink()
            except OSError:
                pass
        raise
    return chunk_paths


def _chunk_base(path: Path) -> tuple[Path, int] | None:
    match = CHUNK_PATTERN.fullmatch(path.name)
    if not match:
        return None
    base = path.with_name(match.group("base"))
    if base.suffix.lower() != ".zip":
        raise ValueError(f"Chunk does not belong to a .zip archive: {path}")
    return base, int(match.group("number"))


def find_archive_parts(
    archive_or_chunk: str | os.PathLike[str],
) -> list[Path]:
    """Find a complete archive or all contiguous chunks for an archive.

    A chunk path may be any member of the set, although the interactive UI
    asks for the first chunk.  Numbering must start at 1 and have no gaps.
    """

    supplied = _as_path(archive_or_chunk)
    if not supplied.is_file():
        raise FileNotFoundError(f"File not found: {supplied}")

    chunk_info = _chunk_base(supplied)
    if chunk_info is None:
        return [supplied]

    base, _ = chunk_info
    candidates: dict[int, Path] = {}
    prefix = f"{base.name}.part"
    for candidate in base.parent.iterdir():
        if not candidate.is_file() or not candidate.name.startswith(prefix):
            continue
        match = CHUNK_PATTERN.fullmatch(candidate.name)
        if match and match.group("base") == base.name:
            candidates[int(match.group("number"))] = candidate

    if not candidates:
        raise FileNotFoundError(f"No chunks found for {base}")

    numbers = sorted(candidates)
    if not numbers or numbers[0] != 1:
        raise ValueError("Archive chunk numbering must start at 1")

    expected = list(range(1, max(candidates) + 1))
    if numbers != expected:
        missing = sorted(set(expected) - set(candidates))
        missing_text = ", ".join(str(number) for number in missing)
        raise ValueError(f"Missing archive chunk(s): {missing_text}")
    return [candidates[number] for number in expected]


def _check_archive_output_available(archive_path: Path, chunk_size: int | None) -> None:
    paths = [archive_path]
    if chunk_size is not None:
        # The exact number of chunks is not known until the ZIP is written;
        # split_file performs the definitive per-chunk collision check.
        paths = [archive_path]
    for path in paths:
        if path.exists():
            raise FileExistsError(f"Output already exists: {path}")


def encrypt_file(
    source_file: str | os.PathLike[str],
    destination_directory: str | os.PathLike[str],
    password: str,
    chunk_size: int | None = None,
) -> list[Path]:
    """Create an AES-encrypted ZIP containing one file.

    Returns the resulting ZIP path, or the paths of all chunks when
    ``chunk_size`` is provided.  File contents are copied in binary mode, so
    text and binary file types are handled identically.
    """

    _require_pyzipper()
    source = _as_path(source_file)
    if not source.is_file():
        raise FileNotFoundError(f"File not found: {source}")
    if not isinstance(password, str) or not password:
        raise ValueError("Password must not be empty")
    if chunk_size is not None and (
        not isinstance(chunk_size, int) or isinstance(chunk_size, bool) or chunk_size <= 0
    ):
        raise ValueError("Chunk size must be a positive integer number of bytes")

    destination = _ensure_directory(destination_directory)
    archive = _archive_path(source, destination)
    _check_archive_output_available(archive, chunk_size)

    try:
        with pyzipper.AESZipFile(
            archive,
            mode="w",
            compression=pyzipper.ZIP_DEFLATED,
            encryption=pyzipper.WZ_AES,
        ) as zip_file:
            zip_file.setpassword(password.encode("utf-8"))
            zip_file.write(source, arcname=source.name)

        if chunk_size is None:
            return [archive]

        return split_file(archive, chunk_size)
    except Exception:
        # Do not leave a partially written un-split archive behind.  Chunks
        # are cleaned by split_file itself if it fails.
        if archive.exists():
            try:
                archive.unlink()
            except OSError:
                pass
        raise


def _safe_member_name(member_name: str) -> str:
    # This application creates one top-level file.  Taking only the final
    # component also prevents a malicious archive from writing outside the
    # selected destination directory.
    name = Path(member_name).name
    if not name or name in {".", ".."}:
        raise ValueError("The archive contains an invalid file name")
    return name


def _join_chunks(parts: Iterable[Path], output: Path) -> None:
    with output.open("wb") as combined:
        for part in parts:
            with part.open("rb") as source:
                shutil.copyfileobj(source, combined, length=1024 * 1024)


def decrypt_file(
    archive_or_chunk: str | os.PathLike[str],
    destination_directory: str | os.PathLike[str],
    password: str,
) -> Path:
    """Decrypt an encrypted ZIP (or its numbered chunks) into a directory."""

    _require_pyzipper()
    if not isinstance(password, str) or not password:
        raise ValueError("Password must not be empty")

    parts = find_archive_parts(archive_or_chunk)
    destination = _ensure_directory(destination_directory)
    temporary_directory: tempfile.TemporaryDirectory[str] | None = None
    archive = parts[0]

    try:
        if len(parts) > 1:
            temporary_directory = tempfile.TemporaryDirectory(prefix=f"{APP_NAME}-")
            archive = Path(temporary_directory.name) / "combined.zip"
            _join_chunks(parts, archive)

        with pyzipper.AESZipFile(archive, mode="r") as zip_file:
            zip_file.setpassword(password.encode("utf-8"))
            members = [member for member in zip_file.infolist() if not member.is_dir()]
            if len(members) != 1:
                raise ValueError(
                    "The archive must contain exactly one file; "
                    f"found {len(members)}"
                )

            member = members[0]
            output = destination / _safe_member_name(member.filename)
            if output.exists():
                raise FileExistsError(f"Output already exists: {output}")

            try:
                with zip_file.open(member, mode="r") as source, output.open("xb") as target:
                    shutil.copyfileobj(source, target, length=1024 * 1024)
            except Exception:
                if output.exists():
                    try:
                        output.unlink()
                    except OSError:
                        pass
                raise
            return output
    finally:
        if temporary_directory is not None:
            temporary_directory.cleanup()


class PasswordManager:
    """Create and verify the app password without storing it in plain text."""

    def __init__(self, config_path: str | os.PathLike[str] | None = None) -> None:
        if config_path is None:
            config_path = os.environ.get(
                "FILEZIPPER_CONFIG",
                str(Path.home() / ".filezipper" / "config.json"),
            )
        self.config_path = _as_path(config_path)

    @staticmethod
    def _digest(password: str, salt: bytes, iterations: int) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations
        )

    def _save_password(self, password: str) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        salt = secrets.token_bytes(16)
        config = {
            "algorithm": "PBKDF2-HMAC-SHA256",
            "iterations": PASSWORD_ITERATIONS,
            "salt": salt.hex(),
            "digest": self._digest(password, salt, PASSWORD_ITERATIONS).hex(),
        }
        with self.config_path.open("w", encoding="utf-8") as config_file:
            json.dump(config, config_file, indent=2)
            config_file.write("\n")
        try:
            self.config_path.chmod(0o600)
        except OSError:
            # chmod is not meaningful on some Windows file systems.
            pass

    def _password_matches(self, password: str) -> bool:
        try:
            with self.config_path.open("r", encoding="utf-8") as config_file:
                config = json.load(config_file)
            salt = bytes.fromhex(config["salt"])
            iterations = int(config["iterations"])
            expected = bytes.fromhex(config["digest"])
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Cannot read password configuration: {self.config_path}") from exc

        actual = self._digest(password, salt, iterations)
        return hmac.compare_digest(actual, expected)

    def get_password(self) -> str:
        """Get the configured password, creating it on the first run."""

        if not self.config_path.exists():
            while True:
                password = getpass.getpass("Create an encryption password: ")
                if not password:
                    print("The password cannot be empty.")
                    continue
                confirmation = getpass.getpass("Confirm the encryption password: ")
                if password != confirmation:
                    print("The passwords do not match. Please try again.")
                    continue
                self._save_password(password)
                return password

        while True:
            password = getpass.getpass("Encryption password: ")
            if self._password_matches(password):
                return password
            print("Incorrect password. Please try again.")


def _prompt_action() -> str:
    while True:
        choice = input(
            "Choose an action: [e]ncrypt and zip a file, or [d]ecrypt an existing zip: "
        ).strip().lower()
        if choice in {"e", "encrypt", "1"}:
            return "encrypt"
        if choice in {"d", "decrypt", "2"}:
            return "decrypt"
        print("Please enter e/encrypt or d/decrypt.")


def _prompt_existing_file(prompt: str) -> Path:
    while True:
        path = normalize_path(input(prompt))
        if path.is_file():
            return path
        print(f"That file does not exist: {path}")


def _prompt_yes_no(prompt: str) -> bool:
    while True:
        answer = input(f"{prompt} [y/n]: ").strip().lower()
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        print("Please answer y or n.")


def _prompt_chunk_size() -> int:
    while True:
        value = input("Chunk size in megabytes (for example, 100 or 0.5): ")
        try:
            return megabytes_to_bytes(value)
        except ValueError as error:
            print(error)


def _prompt_destination() -> Path:
    while True:
        destination = normalize_path(input("Directory where the output should be saved: "))
        try:
            return _ensure_directory(destination)
        except (OSError, ValueError) as error:
            print(f"Cannot use that directory: {error}")


def main() -> int:
    print("FileZipper - AES-encrypted ZIP files")
    try:
        action = _prompt_action()
        if action == "encrypt":
            source = _prompt_existing_file("Path to the file to encrypt and zip: ")
            split = _prompt_yes_no("Do you want the encrypted ZIP split into chunks?")
            chunk_size = _prompt_chunk_size() if split else None
            password = PasswordManager().get_password()
            destination = _prompt_destination()
            outputs = encrypt_file(source, destination, password, chunk_size)
            print("Created:")
            for output in outputs:
                print(f"  {output}")
        else:
            archive = _prompt_existing_file(
                "Path to the encrypted .zip or one of its .zip.partNNN chunks: "
            )
            password = PasswordManager().get_password()
            destination = _prompt_destination()
            output = decrypt_file(archive, destination, password)
            print(f"Decrypted file: {output}")
        return 0
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 130
    except (FileExistsError, FileNotFoundError, NotADirectoryError, ValueError, RuntimeError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
