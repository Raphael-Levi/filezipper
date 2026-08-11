from __future__ import annotations

import io
import os
import re
import tempfile
import unittest
from contextlib import chdir, redirect_stdout
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import filezipper


class FileZipperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.source = self.root / "binary file.bin"
        # Include bytes that must not be decoded or transformed.
        self.source_bytes = bytes(range(256)) * 32 + b"\x00\xff\x00"
        self.source.write_bytes(self.source_bytes)
        self.output = self.root / "output"
        self.password = "correct horse battery staple"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_normalize_path_removes_quotes_and_accepts_backslashes(self) -> None:
        path_as_backslashes = str(self.source).replace(os.sep, "\\")
        pasted = f'"{path_as_backslashes}"'
        self.assertEqual(filezipper.normalize_path(pasted), self.source)

    def test_normalize_path_decodes_shell_escaped_spaces(self) -> None:
        shell_style = str(self.source).replace(" ", r"\ ")
        self.assertEqual(filezipper.normalize_path(shell_style), self.source)

    def test_existing_file_prompt_accepts_shell_escaped_space(self) -> None:
        shell_style = str(self.source).replace(" ", r"\ ")
        with patch("builtins.input", return_value=shell_style):
            self.assertEqual(filezipper._prompt_existing_file("Path: "), self.source)

    def test_megabytes_to_bytes_accepts_decimal_and_rejects_invalid_values(self) -> None:
        self.assertEqual(filezipper.megabytes_to_bytes("0.5"), 512 * 1024)
        self.assertEqual(filezipper.megabytes_to_bytes("1"), 1024 * 1024)
        for invalid in ("0", "-1", "not a number", "inf"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    filezipper.megabytes_to_bytes(invalid)

    def test_default_destination_is_the_filezipper_folder(self) -> None:
        with chdir(self.root):
            with patch(
                "filezipper.uuid.uuid4",
                return_value=UUID("12345678-1234-5678-1234-567812345678"),
            ):
                outputs = filezipper.encrypt_file(self.source, self.password)
                output_directory = outputs[0].resolve().parent
        self.assertEqual(output_directory, (self.root / "filezipper").resolve())
        self.assertTrue((self.root / "filezipper" / filezipper.METADATA_FILENAME).is_file())

    def test_encrypt_uses_uuid_name_and_updates_encrypted_metadata(self) -> None:
        outputs = filezipper.encrypt_file(
            self.source, self.password, destination_directory=self.output
        )
        self.assertEqual(len(outputs), 1)
        self.assertRegex(outputs[0].name, r"^[0-9a-f-]{36}\.zip$")
        self.assertTrue(UUID(outputs[0].stem))
        self.assertTrue(outputs[0].is_file())
        archive_bytes = outputs[0].read_bytes()
        self.assertNotEqual(archive_bytes, self.source_bytes)
        self.assertNotIn(self.source.name.encode("utf-8"), archive_bytes)

        metadata_path = self.output / filezipper.METADATA_FILENAME
        self.assertTrue(metadata_path.is_file())
        self.assertNotIn(self.source.name.encode("utf-8"), metadata_path.read_bytes())
        metadata = filezipper._load_metadata(metadata_path, self.password)
        record = metadata["files"][outputs[0].stem]
        self.assertEqual(record["uuid"], outputs[0].stem)
        self.assertEqual(record["original_filename"], self.source.name)
        self.assertEqual(record["archive_files"], [outputs[0].name])
        self.assertEqual(record["size_bytes"], len(self.source_bytes))
        self.assertIsNone(record["chunk_size_bytes"])

    def test_metadata_requires_the_same_password_as_archives(self) -> None:
        filezipper.encrypt_file(
            self.source, self.password, destination_directory=self.output
        )
        with self.assertRaises(ValueError):
            filezipper._load_metadata(
                self.output / filezipper.METADATA_FILENAME, "wrong password"
            )

    def test_encrypt_split_creates_uuid_chunks_and_metadata_record(self) -> None:
        outputs = filezipper.encrypt_file(
            self.source,
            self.password,
            chunk_size=100,
            destination_directory=self.output,
        )
        self.assertGreater(len(outputs), 1)
        self.assertTrue(all(path.is_file() for path in outputs))
        self.assertTrue(all(re.fullmatch(r"[0-9a-f-]{36}\.zip\.part\d{3,}", path.name) for path in outputs))
        self.assertFalse((self.output / f"{outputs[0].stem}").exists())

        archive_id = outputs[0].name.split(".zip", 1)[0]
        metadata = filezipper._load_metadata(
            self.output / filezipper.METADATA_FILENAME, self.password
        )
        self.assertEqual(metadata["files"][archive_id]["archive_files"], [path.name for path in outputs])
        self.assertEqual(metadata["files"][archive_id]["chunk_size_bytes"], 100)

    def test_existing_uuid_output_is_not_overwritten(self) -> None:
        archive_id = UUID("12345678-1234-5678-1234-567812345678")
        self.output.mkdir()
        archive = self.output / f"{archive_id}.zip"
        archive.write_bytes(b"keep this")
        with patch("filezipper.uuid.uuid4", return_value=archive_id):
            with self.assertRaises(FileExistsError):
                filezipper.encrypt_file(
                    self.source, self.password, destination_directory=self.output
                )
        self.assertEqual(archive.read_bytes(), b"keep this")

    def test_password_manager_creates_verifier_and_validates_password(self) -> None:
        config = self.root / ".filezipper" / "config.json"
        manager = filezipper.PasswordManager(config)
        with patch.object(
            filezipper.getpass,
            "getpass",
            side_effect=[self.password, self.password],
        ):
            self.assertEqual(manager.get_password(), self.password)
        self.assertTrue(config.is_file())
        self.assertNotIn(self.password, config.read_text(encoding="utf-8"))

        with patch.object(filezipper.getpass, "getpass", return_value=self.password):
            self.assertEqual(manager.get_password(), self.password)

    def test_cli_has_no_action_or_destination_prompt(self) -> None:
        output = Path("filezipper/12345678-1234-5678-1234-567812345678.zip")
        stdout = io.StringIO()
        with (
            patch.object(filezipper, "_prompt_existing_file", return_value=self.source),
            patch.object(filezipper, "_prompt_yes_no", return_value=False),
            patch.object(filezipper.PasswordManager, "get_password", return_value=self.password),
            patch.object(filezipper, "encrypt_file", return_value=[output]) as encrypt,
            redirect_stdout(stdout),
        ):
            self.assertEqual(filezipper.main(), 0)

        encrypt.assert_called_once_with(self.source, self.password, None)
        text = stdout.getvalue().lower()
        self.assertNotIn("choose an action", text)
        self.assertNotIn("destination", text)
        self.assertIn("./filezipper", text)

    def test_user_archive_decryption_is_removed(self) -> None:
        self.assertFalse(hasattr(filezipper, "decrypt_file"))
        self.assertFalse(hasattr(filezipper, "find_archive_parts"))


if __name__ == "__main__":
    unittest.main()
