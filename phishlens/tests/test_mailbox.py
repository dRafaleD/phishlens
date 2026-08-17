from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from phishlens.mailbox import fetch_messages  # noqa: E402


RAW_MESSAGE = b"From: sender@example.com\r\nSubject: Test\r\n\r\nHello"


class FakeImap:
    instance: "FakeImap | None" = None

    def __init__(self, **kwargs):
        self.connection_options = kwargs
        self.selected: tuple[str, bool] | None = None
        self.fetch_queries: list[tuple[bytes, str]] = []
        self.logged_out = False
        FakeImap.instance = self

    def login(self, username: str, password: str):
        self.credentials = (username, password)
        return "OK", []

    def select(self, folder: str, readonly: bool = False):
        self.selected = (folder, readonly)
        return "OK", [b"2"]

    def search(self, charset, criterion: str):
        self.search_query = (charset, criterion)
        return "OK", [b"10 11"]

    def fetch(self, identifier: bytes, query: str):
        self.fetch_queries.append((identifier, query))
        return "OK", [(b"response", RAW_MESSAGE)]

    def logout(self):
        self.logged_out = True
        return "BYE", []


class MailboxTests(unittest.TestCase):
    @patch("phishlens.mailbox.imaplib.IMAP4_SSL", FakeImap)
    def test_fetches_newest_messages_read_only_with_peek(self) -> None:
        messages = fetch_messages(
            provider="gmail",
            username="person@example.com",
            secret="app-password",
            auth="password",
            limit=2,
            unread_only=True,
        )

        instance = FakeImap.instance
        self.assertIsNotNone(instance)
        self.assertEqual(instance.selected, ("INBOX", True))
        self.assertEqual(instance.search_query, (None, "UNSEEN"))
        self.assertEqual(instance.fetch_queries, [(b"11", "(BODY.PEEK[])"), (b"10", "(BODY.PEEK[])")])
        self.assertEqual([message.source for message in messages], ["imap://gmail/INBOX/11", "imap://gmail/INBOX/10"])
        self.assertTrue(instance.logged_out)


if __name__ == "__main__":
    unittest.main()
