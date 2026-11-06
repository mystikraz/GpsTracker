from __future__ import annotations

import io
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

try:
    from fleet_tracker.cli import _read_secret, build_parser
except ImportError as error:  # pragma: no cover - minimal local interpreters
    _read_secret = None
    build_parser = None
    CLI_IMPORT_ERROR = str(error)
else:
    CLI_IMPORT_ERROR = ""


@unittest.skipIf(build_parser is None, f"CLI dependencies unavailable: {CLI_IMPORT_ERROR}")
class CliSecretHandlingTests(unittest.TestCase):
    def test_secret_values_are_rejected_as_argv(self) -> None:
        with self.assertRaises(SystemExit):
            build_parser().parse_args(
                [
                    "provision-device",
                    "--org-id",
                    "org",
                    "--vehicle-id",
                    "vehicle",
                    "--terminal-id",
                    "071604184647",
                    "--initial-auth-code",
                    "71604184647",
                ]
            )
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["rotate-device-secret", "--terminal-id", "071604184647", "--auth-code", "71604184647"])

    def test_secret_is_read_from_environment_without_output(self) -> None:
        with patch.dict(os.environ, {"INITIAL_AUTH_CODE": "71604184647"}, clear=False):
            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(output):
                value = _read_secret("INITIAL_AUTH_CODE", "secret: ")
        self.assertEqual(value, "71604184647")
        self.assertNotIn(value, output.getvalue())

    def test_secret_is_read_from_stdin_without_output(self) -> None:
        with patch.dict(os.environ, {}, clear=True), patch("sys.stdin", io.StringIO("71604184647\n")):
            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(output):
                value = _read_secret("INITIAL_AUTH_CODE", "secret: ")
        self.assertEqual(value, "71604184647")
        self.assertNotIn(value, output.getvalue())

    def test_secret_is_not_in_cli_error_text(self) -> None:
        stderr = io.StringIO()
        with self.assertRaises(SystemExit), redirect_stderr(stderr):
            build_parser().parse_args(["rotate-device-secret", "--terminal-id", "071604184647", "--auth-code", "71604184647"])
        self.assertNotIn("71604184647", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
