from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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
            self.assertEqual(
                filezipper._prompt_existing_file("Path: "), self.source
            )

    def test_megabytes_to_bytes_accepts_decimal_and_rejects_invalid_values(self) -> None:
        self.assertEqual(filezipper.megabytes_to_bytes("0.5"), 512 * 1024)
        self.assertEqual(filezipper.megabytes_to_bytes("1"), 1024 * 1024)
        for invalid in ("0", "-1", "not a number", "inf"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    filezipper.megabytes_to_bytes(invalid)

    def test_encrypt_and_decrypt_binary_file(self) -> None:
        outputs = filezipper.encrypt_file(self.source, self.output, self.password)
        self.assertEqual(len(outputs), 1)
        self.assertEqual(outputs[0].name, "binary file.bin.zip")
        self.assertTrue(outputs[0].is_file())
        self.assertNotEqual(outputs[0].read_bytes(), self.source_bytes)

        restored_dir = self.root / "restored"
        restored = filezipper.decrypt_file(outputs[0], restored_dir, self.password)
        self.assertEqual(restored.read_bytes(), self.source_bytes)
        self.assertEqual(restored.name, self.source.name)

    def test_encrypt_split_and_decrypt_from_a_chunk(self) -> None:
        outputs = filezipper.encrypt_file(
            self.source,
            self.output,
            self.password,
            chunk_size=100,
        )
        self.assertGreater(len(outputs), 1)
        self.assertEqual(outputs[0].name, "binary file.bin.zip.part001")
        self.assertTrue(all(path.is_file() for path in outputs))
        self.assertFalse((self.output / "binary file.bin.zip").exists())

        # Supplying a later chunk still finds the complete contiguous set.
        restored = filezipper.decrypt_file(
            outputs[-1], self.root / "restored split", self.password
        )
        self.assertEqual(restored.read_bytes(), self.source_bytes)

    def test_missing_chunk_is_reported(self) -> None:
        outputs = filezipper.encrypt_file(
            self.source,
            self.output,
            self.password,
            chunk_size=100,
        )
        outputs[1].unlink()
        with self.assertRaises(ValueError):
            filezipper.find_archive_parts(outputs[0])

    def test_existing_output_is_not_overwritten(self) -> None:
        self.output.mkdir()
        archive = self.output / "binary file.bin.zip"
        archive.write_bytes(b"keep this")
        with self.assertRaises(FileExistsError):
            filezipper.encrypt_file(self.source, self.output, self.password)
        self.assertEqual(archive.read_bytes(), b"keep this")

    def test_password_manager_creates_verifier_and_validates_password(self) -> None:
        config = self.root / ".filezipper" / "config.json"
        manager = filezipper.PasswordManager(config)
        with patch.object(filezipper.getpass, "getpass", side_effect=[self.password, self.password]):
            self.assertEqual(manager.get_password(), self.password)
        self.assertTrue(config.is_file())
        self.assertNotIn(self.password, config.read_text(encoding="utf-8"))

        with patch.object(filezipper.getpass, "getpass", return_value=self.password):
            self.assertEqual(manager.get_password(), self.password)


if __name__ == "__main__":
    unittest.main()
