#!/usr/bin/env python3
"""Create AES-encrypted ZIP archives for the FileBrowser-backed archive folder.

The command-line interface only creates archives. FileBrowser Quantum manages
folders and file operations for the archive folder; this module deliberately
does not decrypt user archives.
"""

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import math
import os
import secrets
import sys
import uuid
from pathlib import Path
from typing import Any

try:
    import pyzipper
except ImportError:  # pragma: no cover - exercised by an installation error
    pyzipper = None  # type: ignore[assignment]


PASSWORD_ITERATIONS = 600_000

# The CLI intentionally has no destination prompt.  Keeping this relative to
# the working directory makes the promised ``./filezipper`` location explicit
# and also makes the Docker Compose bind mount predictable.
ARCHIVE_DIRECTORY = Path("filezipper")
METADATA_FILENAME = "metadata.zip"
METADATA_MEMBER_NAME = "metadata.json"
METADATA_VERSION = 1


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


def _archive_path(archive_id: str, destination: Path) -> Path:
    """Return the archive path for a UUID-based archive identifier."""

    return destination / f"{archive_id}.zip"


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


def _empty_metadata() -> dict[str, Any]:
    return {"version": METADATA_VERSION, "files": {}}


def _metadata_path(destination: Path) -> Path:
    return destination / METADATA_FILENAME


def _load_metadata(metadata_path: Path, password: str) -> dict[str, Any]:
    """Load the one encrypted metadata document, or return an empty one."""

    _require_pyzipper()
    if not metadata_path.exists():
        return _empty_metadata()

    try:
        with pyzipper.AESZipFile(metadata_path, mode="r") as zip_file:
            zip_file.setpassword(password.encode("utf-8"))
            members = [member for member in zip_file.infolist() if not member.is_dir()]
            if len(members) != 1 or members[0].filename != METADATA_MEMBER_NAME:
                raise ValueError(
                    f"{METADATA_FILENAME} must contain exactly {METADATA_MEMBER_NAME}"
                )
            metadata = json.loads(zip_file.read(members[0]).decode("utf-8"))
    except (OSError, RuntimeError, UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError) as error:
        raise ValueError(
            f"Cannot read encrypted metadata at {metadata_path}; "
            "check the encryption password and do not replace the metadata file"
        ) from error

    if not isinstance(metadata, dict) or metadata.get("version") != METADATA_VERSION:
        raise ValueError(f"Unsupported metadata format in {metadata_path}")
    if not isinstance(metadata.get("files"), dict):
        raise ValueError(f"Invalid metadata file: {metadata_path}")
    return metadata


def _save_metadata(metadata_path: Path, metadata: dict[str, Any], password: str) -> None:
    """Atomically replace the encrypted metadata ZIP."""

    _require_pyzipper()
    temporary_path = metadata_path.with_name(
        f".{metadata_path.name}.{uuid.uuid4().hex}.tmp"
    )
    try:
        with pyzipper.AESZipFile(
            temporary_path,
            mode="w",
            compression=pyzipper.ZIP_DEFLATED,
            encryption=pyzipper.WZ_AES,
        ) as zip_file:
            zip_file.setpassword(password.encode("utf-8"))
            zip_file.writestr(
                METADATA_MEMBER_NAME,
                json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True).encode(
                    "utf-8"
                ),
            )
        temporary_path.replace(metadata_path)
        try:
            metadata_path.chmod(0o600)
        except OSError:
            # chmod is not meaningful on some Windows file systems.
            pass
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def encrypt_file(
    source_file: str | os.PathLike[str],
    password: str,
    chunk_size: int | None = None,
    *,
    destination_directory: str | os.PathLike[str] = ARCHIVE_DIRECTORY,
) -> list[Path]:
    """Create a UUID-named AES-encrypted ZIP and update encrypted metadata.

    The destination argument is keyword-only so the command-line interface
    cannot accidentally turn it into a user prompt.  The CLI always uses
    ``./filezipper``; the keyword remains useful for isolated tests and for
    callers embedding the encryption function.

    The returned paths are either the UUID ZIP or all of its numbered chunks.
    The original filename is stored only in ``metadata.zip``, which is itself
    AES-encrypted with the same password.
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
    metadata_path = _metadata_path(destination)
    metadata = _load_metadata(metadata_path, password)
    archive_id = str(uuid.uuid4())
    archive = _archive_path(archive_id, destination)
    if archive.exists():
        raise FileExistsError(f"Output already exists: {archive}")

    created_paths: list[Path] = [archive]
    try:
        with pyzipper.AESZipFile(
            archive,
            mode="w",
            compression=pyzipper.ZIP_DEFLATED,
            encryption=pyzipper.WZ_AES,
        ) as zip_file:
            zip_file.setpassword(password.encode("utf-8"))
            # Keep the source name out of the archive directory as well as
            # out of the FileBrowser-visible filename.  The encrypted
            # metadata index is the source of truth for the original name.
            zip_file.write(source, arcname=archive_id)

        outputs = [archive] if chunk_size is None else split_file(archive, chunk_size)
        created_paths = [archive, *outputs]
        metadata["files"][archive_id] = {
            "uuid": archive_id,
            "original_filename": source.name,
            "archive_files": [output.name for output in outputs],
            "size_bytes": source.stat().st_size,
            "chunk_size_bytes": chunk_size,
        }
        _save_metadata(metadata_path, metadata, password)
        return outputs
    except Exception:
        # Metadata is written atomically.  If it cannot be updated, do not
        # leave an archive whose UUID is absent from the metadata index.
        for path in created_paths:
            try:
                path.unlink()
            except OSError:
                pass
        raise


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


def main() -> int:
    print("FileZipper - AES-encrypted ZIP files")
    try:
        source = _prompt_existing_file("Path to the file to encrypt and zip: ")
        split = _prompt_yes_no("Do you want the encrypted ZIP split into chunks?")
        chunk_size = _prompt_chunk_size() if split else None
        password = PasswordManager().get_password()
        outputs = encrypt_file(source, password, chunk_size)
        print(f"Created in ./{ARCHIVE_DIRECTORY}:")
        for output in outputs:
            print(f"  {output}")
        print(f"Metadata index: {ARCHIVE_DIRECTORY / METADATA_FILENAME}")
        return 0
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 130
    except (FileExistsError, FileNotFoundError, NotADirectoryError, ValueError, RuntimeError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
