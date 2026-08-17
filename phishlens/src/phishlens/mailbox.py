from __future__ import annotations

import imaplib
import ssl
from dataclasses import dataclass
from email import policy
from email.message import Message
from email.parser import BytesParser


PROVIDERS = {
    "gmail": ("imap.gmail.com", 993),
    "outlook": ("outlook.office365.com", 993),
}


class MailboxError(RuntimeError):
    """Raised when a mailbox cannot be read safely."""


@dataclass(frozen=True)
class MailboxMessage:
    source: str
    message: Message


def _is_ok(status: str | bytes) -> bool:
    if isinstance(status, bytes):
        status = status.decode("ascii", errors="replace")
    return status.upper() == "OK"


def _message_bytes(response: list[object] | tuple[object, ...] | None) -> bytes | None:
    if not response:
        return None
    for item in response:
        if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], bytes):
            return item[1]
    return None


def fetch_messages(
    *,
    provider: str,
    username: str,
    secret: str,
    auth: str,
    folder: str = "INBOX",
    limit: int = 10,
    unread_only: bool = False,
    host: str | None = None,
    port: int | None = None,
) -> list[MailboxMessage]:
    if limit < 1 or limit > 100:
        raise MailboxError("message limit must be between 1 and 100")
    if provider in PROVIDERS:
        default_host, default_port = PROVIDERS[provider]
        host = host or default_host
        port = port or default_port
    elif provider == "custom":
        if not host:
            raise MailboxError("--host is required for a custom provider")
        port = port or 993
    else:
        raise MailboxError(f"unsupported provider: {provider}")
    if auth not in {"password", "oauth2"}:
        raise MailboxError(f"unsupported authentication method: {auth}")

    connection: imaplib.IMAP4_SSL | None = None
    try:
        connection = imaplib.IMAP4_SSL(
            host=host,
            port=port,
            ssl_context=ssl.create_default_context(),
            timeout=30,
        )
        if auth == "oauth2":
            auth_data = f"user={username}\x01auth=Bearer {secret}\x01\x01".encode("utf-8")
            connection.authenticate("XOAUTH2", lambda _: auth_data)
        else:
            connection.login(username, secret)

        status, _ = connection.select(folder, readonly=True)
        if not _is_ok(status):
            raise MailboxError(f"could not open mailbox folder: {folder}")
        criterion = "UNSEEN" if unread_only else "ALL"
        status, search_data = connection.search(None, criterion)
        if not _is_ok(status):
            raise MailboxError(f"mailbox search failed for criterion {criterion}")

        identifiers = search_data[0].split() if search_data and search_data[0] else []
        selected = list(reversed(identifiers[-limit:]))
        messages: list[MailboxMessage] = []
        for identifier in selected:
            status, fetch_data = connection.fetch(identifier, "(BODY.PEEK[])")
            if not _is_ok(status):
                continue
            raw_message = _message_bytes(fetch_data)
            if raw_message is None:
                continue
            parsed = BytesParser(policy=policy.default).parsebytes(raw_message)
            display_id = identifier.decode("ascii", errors="replace")
            messages.append(
                MailboxMessage(
                    source=f"imap://{provider}/{folder}/{display_id}",
                    message=parsed,
                )
            )
        return messages
    except (imaplib.IMAP4.error, OSError, ssl.SSLError) as error:
        raise MailboxError(f"mailbox connection failed: {error}") from error
    finally:
        if connection is not None:
            try:
                connection.logout()
            except (imaplib.IMAP4.error, OSError):
                pass
