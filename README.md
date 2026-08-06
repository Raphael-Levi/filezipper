# FileZipper

A small cross-platform Python 3.11+ command-line program that puts one file
of any type into an AES-encrypted ZIP archive. It can optionally split the
encrypted archive into numbered chunks and join those chunks again when
decrypting.

## Features

- Handles text, images, videos, documents, and other binary files without
  changing their contents.
- Uses an AES-encrypted ZIP format through the single external dependency
  [`pyzipper`](https://pypi.org/project/pyzipper/).
- Accepts paths with or without matching single/double quotes.
- Accepts forward-slash and backslash path separators on every supported OS.
- Recognizes shell-escaped spaces, such as `/Users/me/Untitled\ 1.wav`.
- Splits the encrypted ZIP after encryption, so individual chunks are not
  useful without the password and all chunks.
- Stores only a salted password verifier, never the password itself.

## Installation

From this directory, create a virtual environment if desired and install the
dependency:

```bash
python3 -m venv .venv

# macOS/Linux
. .venv/bin/activate

# Windows PowerShell: .venv\Scripts\Activate.ps1

python -m pip install -r requirements.txt
```

Python 3.11 or newer is supported. The program has also been written to work
with Python 3.14.

## Run the program

```bash
python filezipper.py
```

The program will:

1. Ask whether to encrypt and zip, or decrypt an existing ZIP.
2. Ask for the input path. You can paste paths such as
   `"/home/me/My File.pdf"`, `/Users/me/Untitled\ 1.wav`, or
   `C:\Users\me\My File.pdf`. A backslash before a space is treated as an
   escaped space rather than as a directory separator.
3. When encrypting, ask whether the encrypted ZIP should be split. If yes,
   enter a chunk size in megabytes; decimal values such as `0.5` are accepted.
4. Ask for a destination directory, creating it if necessary.

The first run asks for a password twice and creates a verifier at
`~/.filezipper/config.json` (or the path in the `FILEZIPPER_CONFIG` environment
variable). On later runs the password is requested for each operation. This is
intentional: the actual password is not stored, so losing it means the archive
cannot be decrypted.

### Example output

For an input file named `photo.jpg`, without splitting, the output is:

```text
photo.jpg.zip
```

With splitting, the output is similar to:

```text
photo.jpg.zip.part001
photo.jpg.zip.part002
photo.jpg.zip.part003
```

To decrypt split output, select decrypt and enter the path to any existing
chunk (the first chunk is easiest). The program finds all sibling chunks,
checks that numbering starts at 1 with no gaps, combines them temporarily,
and writes the original file to the selected destination directory.

## Tests

The tests use Python's standard `unittest` module. Install the dependency
first, then run:

```bash
python -m unittest discover -s tests -v
```

The tests cover path normalization, binary content, AES ZIP encryption and
decryption, splitting and rejoining chunks, password setup/verification, and
missing chunk detection.

## Security and format notes

- The ZIP archive is encrypted with AES; it is not merely renamed or hidden.
- A password verifier is saved with restrictive permissions where the
  operating system supports them. It cannot be used to recover the password.
- Do not delete or rename any chunk. A split archive requires every numbered
  chunk.
- The program intentionally handles one input file per archive. It rejects an
  archive containing zero or multiple files when decrypting.
- Existing output files are not overwritten. Choose an empty destination or
  move the previous output first.
