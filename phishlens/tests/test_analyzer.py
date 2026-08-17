from __future__ import annotations

import sys
import unittest
from email import policy
from email.parser import BytesParser
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from phishlens.analyzer import analyze_message  # noqa: E402


def parse_message(raw: str):
    return BytesParser(policy=policy.default).parsebytes(raw.encode("utf-8"))


class AnalyzerTests(unittest.TestCase):
    def test_flags_sender_authentication_and_link_mismatch(self) -> None:
        message = parse_message(
            """From: Bank <alerts@example.com>
Reply-To: support@attacker.test
Return-Path: <bounce@attacker.test>
Subject: Acil: Hesabiniz askiya alindi
Authentication-Results: mx.example; spf=fail; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<p><a href="https://evil.test/login">https://example.com/login</a></p>
"""
        )

        result = analyze_message(message)
        rule_ids = {finding.rule_id for finding in result.findings}

        self.assertEqual(result.verdict, "high-risk")
        self.assertEqual(result.score, 100)
        self.assertIn("REPLY_TO_MISMATCH", rule_ids)
        self.assertIn("AUTH_DMARC_FAIL", rule_ids)
        self.assertIn("URL_LABEL_MISMATCH", rule_ids)

    def test_low_risk_plain_message(self) -> None:
        message = parse_message(
            """From: Alice <alice@example.com>
Reply-To: alice@example.com
Return-Path: <alice@example.com>
Subject: Weekly notes
Authentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain; charset=utf-8

Hello team, the meeting starts at ten.
"""
        )

        result = analyze_message(message)

        self.assertEqual(result.score, 0)
        self.assertEqual(result.verdict, "low-risk")
        self.assertEqual(result.findings, [])

    def test_flags_dangerous_double_extension_attachment(self) -> None:
        message = parse_message(
            """From: Sender <sender@example.com>
Subject: Document
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=demo

--demo
Content-Type: text/plain

See attachment.
--demo
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA
--demo--
"""
        )

        result = analyze_message(message)
        rule_ids = {finding.rule_id for finding in result.findings}

        self.assertIn("ATTACHMENT_EXECUTABLE", rule_ids)
        self.assertIn("ATTACHMENT_DOUBLE_EXTENSION", rule_ids)
        self.assertEqual(result.verdict, "high-risk")

    def test_parses_received_spf_fallback(self) -> None:
        message = parse_message(
            """From: Sender <sender@example.com>
Subject: Test
Received-SPF: fail (example.com: domain does not designate 192.0.2.1)
Content-Type: text/plain; charset=utf-8

Hello.
"""
        )

        result = analyze_message(message)

        self.assertEqual(result.authentication, {"spf": "fail"})
        self.assertIn("AUTH_SPF_FAIL", {finding.rule_id for finding in result.findings})

    def test_flags_credential_form_and_brand_impersonation(self) -> None:
        message = parse_message(
            """From: Microsoft Security <notice@security-alerts.test>
Subject: Account notice
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<p>Verify your password now to keep your account active.</p>
<form action="https://microsoft-login.test/account/verify">
  <input type="password" name="password">
  <a href="https://microsoft-login.test/account/verify">Continue</a>
</form>
"""
        )

        result = analyze_message(message)
        rule_ids = {finding.rule_id for finding in result.findings}

        self.assertIn("SENDER_BRAND_MISMATCH", rule_ids)
        self.assertIn("BODY_CREDENTIAL_REQUEST", rule_ids)
        self.assertIn("HTML_PASSWORD_FORM", rule_ids)
        self.assertIn("URL_BRAND_LOOKALIKE", rule_ids)
        self.assertIn("URL_SENDER_DOMAIN_MISMATCH", rule_ids)
        self.assertEqual(result.verdict, "high-risk")

    def test_flags_qr_lure_redirect_and_active_content(self) -> None:
        message = parse_message(
            """From: Billing <billing@example.com>
Subject: Document
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=demo

--demo
Content-Type: text/html; charset=utf-8

<p>Scan the QR code and verify your account.</p>
<img src="cid:qr-code">
<a href="https://example.com/go?url=https%3A%2F%2Fevil.test">Open</a>
--demo
Content-Type: text/html
Content-Disposition: attachment; filename="invoice.html"

<html>Open me</html>
--demo--
"""
        )

        result = analyze_message(message)
        rule_ids = {finding.rule_id for finding in result.findings}

        self.assertIn("QR_CODE_LURE", rule_ids)
        self.assertIn("URL_NESTED_REDIRECT", rule_ids)
        self.assertIn("ATTACHMENT_ACTIVE_CONTENT", rule_ids)

    def test_allows_related_official_brand_login_domain(self) -> None:
        message = parse_message(
            """From: Microsoft <alerts@microsoft.com>
Subject: Sign-in notice
Content-Type: text/plain; charset=utf-8

Review the sign-in at https://login.microsoftonline.com/account
"""
        )

        result = analyze_message(message)
        rule_ids = {finding.rule_id for finding in result.findings}

        self.assertNotIn("SENDER_BRAND_MISMATCH", rule_ids)
        self.assertNotIn("URL_BRAND_LOOKALIKE", rule_ids)
        self.assertNotIn("URL_SENDER_DOMAIN_MISMATCH", rule_ids)

    def test_malformed_url_does_not_crash_analysis(self) -> None:
        message = parse_message(
            """From: Sender <sender@example.com>
Subject: Broken link
Content-Type: text/plain; charset=utf-8

Open http://[broken/login for details.
"""
        )

        result = analyze_message(message)

        self.assertEqual(len(result.urls), 1)
        self.assertEqual(result.urls[0].host, "")


if __name__ == "__main__":
    unittest.main()
