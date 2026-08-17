from __future__ import annotations

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from phishlens.cli import main  # noqa: E402


SAFE_MESSAGE = (
    "From: Alice <alice@example.com>\n"
    "Subject: Weekly notes\n"
    "Authentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass\n"
    "Content-Type: text/plain; charset=utf-8\n\n"
    "Hello team.\n"
)


class CliTests(unittest.TestCase):
    def test_legacy_file_command_still_works(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            message_path = Path(temporary_directory) / "safe.eml"
            message_path.write_text(SAFE_MESSAGE, encoding="utf-8")
            output = io.StringIO()

            with redirect_stdout(output):
                exit_code = main([str(message_path)])

            self.assertEqual(exit_code, 0)
            self.assertIn("PhishLens analysis", output.getvalue())

    def test_scans_eml_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "safe.eml").write_text(SAFE_MESSAGE, encoding="utf-8")
            (root / "ignored.txt").write_text("not an email", encoding="utf-8")
            output = io.StringIO()

            with redirect_stdout(output):
                exit_code = main(["scan", str(root)])

            self.assertEqual(exit_code, 0)
            self.assertIn("Messages: 1", output.getvalue())

    def test_gui_command_invokes_launcher(self) -> None:
        with patch("phishlens.cli.launch_gui") as launch_gui:
            exit_code = main(["gui"])

        self.assertEqual(exit_code, 0)
        launch_gui.assert_called_once_with(initial_model_path=None)


if __name__ == "__main__":
    unittest.main()
