# FileZipper

FileZipper creates AES-encrypted ZIP archives and puts them in one shared
`./filezipper` directory. FileBrowser Quantum provides the web interface for
browsing that directory and for creating folders, uploading, renaming, moving,
and deleting archive files. FileZipper does **not** decrypt user archives.

## Design

- Every source file becomes an archive named with a UUID, for example
  `550e8400-e29b-41d4-a716-446655440000.zip`.
- Split archives use the same UUID followed by `.zip.part001`,
  `.zip.part002`, and so on.
- `./filezipper/metadata.zip` is the one metadata file. It contains an
  encrypted `metadata.json` member mapping each UUID to its original filename,
  archive parts, source size, and chunk size.
- The metadata ZIP uses AES and the exact same password as the source archives.
  The original filename is therefore not exposed by the metadata file.
- The CLI never asks for an output directory. It always writes to
  `./filezipper`, relative to the directory from which it is run.
- FileBrowser is deliberately an external, established file manager rather
  than a file browser implemented in this project. Its own persistent SQLite
  database stores browser users and its search index; it is separate from the
  encrypted FileZipper metadata.

The metadata records the UUID and filenames, not a permanent directory path.
Therefore a UUID archive can be moved into a FileBrowser folder without
changing the mapping. Move every part of a split archive together, and keep
`metadata.zip` at the root of the FileZipper source.

## File browser research and choice

**Selected: [FileBrowser Quantum](https://github.com/gtsteffaniak/filebrowser)**

It is a modern, responsive, self-hosted web file manager and an actively
maintained fork of the original
[File Browser](https://github.com/filebrowser/filebrowser) project. Quantum
supports a local filesystem source, persistent password authentication, folder
creation, upload/download, rename, move, delete, search, and per-source
permissions. It has Docker images for macOS/Windows Docker Desktop and Linux
on both `amd64` and `arm64`.

The original File Browser also satisfies the basic file-management
requirements, but Quantum is the better fit here because it adds a more modern
UI, active search, more authentication options, and a documented YAML
configuration. Relevant primary documentation:

- [Quantum project](https://github.com/gtsteffaniak/filebrowser)
- [Docker setup](https://filebrowserquantum.com/en/docs/getting-started/docker/)
- [Source configuration](https://filebrowserquantum.com/en/docs/configuration/sources/)
- [User management and per-source permissions](https://filebrowserquantum.com/en/docs/configuration/users/)

This repository includes a pinned integration shape in `docker-compose.yml`
and `filebrowser/config.yaml`. The browser receives only `./filezipper`, not
the rest of the project.

## Installation

Create a virtual environment if desired and install the Python dependency:

```bash
python3 -m venv .venv

# macOS/Linux
. .venv/bin/activate

# Windows PowerShell: .venv\Scripts\Activate.ps1

python -m pip install -r requirements.txt
```

Python 3.11 or newer is supported.

## Start FileBrowser

Docker and Docker Compose are required for the web browser integration.

```bash
mkdir -p filezipper filebrowser/data
cp .env.example .env
```

On Linux, edit `.env` and set `FILEBROWSER_UID` and `FILEBROWSER_GID` to the
user/group that own the mounted directories (the values from `id -u` and
`id -g`). This lets FileBrowser create folders and move files. Docker Desktop
usually handles the bind-mount permissions without this change.

Start the browser:

```bash
docker compose up -d
```

Open <http://localhost:8080>. On a new Quantum installation, use the initial
credentials shown by the container (the quick-start default is `admin` /
`admin`), then immediately change the administrator password in the web UI.
Do not expose this development HTTP endpoint directly to the internet; put it
behind HTTPS and a reverse proxy for remote access.

The Compose file persists `/home/filebrowser/data`, which keeps the browser
account, index, and configuration across restarts. The browser session is
held in its normal web session cookie, so you log in once and can then use the
folder and move operations without logging in for each operation. Logging out,
clearing cookies, or an expired session requires a new login. The FileBrowser
login is intentionally separate from the FileZipper encryption password; the
latter is never passed to Docker or stored in the repository.

The browser user needs `view`, `download`, `modify`, `create`, and `delete`
permissions for the `Encrypted archives` source. The initial administrator has
these permissions. If a non-admin user is created, grant the permissions in
**User Management** → the source scope.

## Run FileZipper

```bash
python filezipper.py
```

The program asks for:

1. the source file path;
2. whether to split the encrypted archive; and
3. a chunk size in megabytes when splitting is enabled.

It then asks for the encryption password and writes all output to
`./filezipper`. There is no decrypt action and no output-path prompt. The first
run asks for a password twice and creates a salted verifier at
`~/.filezipper/config.json` (or the path in `FILEZIPPER_CONFIG`). On later runs
the password is requested for each invocation. The verifier cannot recover a
lost password.

Example output for `photo.jpg`:

```text
Created in ./filezipper:
  filezipper/550e8400-e29b-41d4-a716-446655440000.zip
Metadata index: filezipper/metadata.zip
```

For a split file, all parts share the same UUID:

```text
550e8400-e29b-41d4-a716-446655440000.zip.part001
550e8400-e29b-41d4-a716-446655440000.zip.part002
```

`metadata.zip` must not be renamed, deleted, or edited in FileBrowser. It is
updated by FileZipper whenever a new archive is created. Do not delete or
rename any part of a split archive.

## Tests

Install the dependency first, then run:

```bash
python -m unittest discover -s tests -v
```

The tests cover path normalization, chunking, UUID archive names, encrypted
metadata and password matching, collision protection, password setup, the
absence of the decrypt workflow, and the fact that the CLI has no destination
prompt. The Docker and FileBrowser files are configuration rather than a
second file-browser implementation.

## Security notes

- Archives and metadata use AES through
  [`pyzipper`](https://pypi.org/project/pyzipper/).
- A salted PBKDF2-HMAC-SHA256 password verifier is stored with restrictive
  permissions where supported; the plaintext password is not stored.
- UUID names hide original filenames from the FileBrowser listing, but anyone
  with access to an archive can still download it. UUIDs are identifiers, not
  encryption.
- Do not expose FileBrowser directly to the public internet. Use TLS, a
  reverse proxy, and strong separate browser credentials.
- The project intentionally does not contain a user-file decryption command.
  Restoring an archive requires an external AES-ZIP-compatible tool or a
  separately controlled recovery workflow.
