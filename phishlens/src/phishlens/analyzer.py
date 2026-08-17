from __future__ import annotations

import html
import ipaddress
import re
import unicodedata
from dataclasses import asdict, dataclass
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from .classifier import ModelPrediction, NaiveBayesModel


URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
AUTH_PATTERN = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z_-]+)", re.IGNORECASE)
URGENT_TERMS = {
    "acil",
    "askiya alindi",
    "dogrula",
    "hemen",
    "hesabiniz",
    "odeme",
    "sifreniz",
    "urgent",
    "verify now",
    "account suspended",
    "password expires",
    "immediate action",
}
BODY_PRESSURE_TERMS = URGENT_TERMS | {
    "act now",
    "click now",
    "last chance",
    "son sans",
    "24 saat",
    "islem yapin",
    "tiklayin",
    "within 24 hours",
}
CREDENTIAL_TERMS = {
    "account details",
    "credential",
    "dogrulama kodu",
    "giris bilgileri",
    "hesap bilgileri",
    "login",
    "one-time password",
    "otp",
    "parola",
    "password",
    "recovery phrase",
    "seed phrase",
    "sifre",
    "verification code",
}
ACTION_TERMS = {
    "confirm",
    "dogrula",
    "enter",
    "giris yap",
    "hemen",
    "open",
    "submit",
    "tikla",
    "update",
    "verify",
}
FINANCIAL_TERMS = {
    "banka hesabi",
    "credit card",
    "crypto",
    "fatura",
    "gift card",
    "iban",
    "invoice",
    "kredi karti",
    "payment",
    "odeme",
    "wire transfer",
}
CREDENTIAL_URL_TERMS = {
    "account",
    "auth",
    "login",
    "password",
    "secure",
    "signin",
    "sso",
    "verify",
    "wallet",
}
REDIRECT_PARAMETER_NAMES = {"continue", "dest", "destination", "next", "redirect", "target", "url"}
BRAND_DOMAINS = {
    "amazon": {"amazon.com"},
    "apple": {"apple.com"},
    "docusign": {"docusign.com"},
    "dropbox": {"dropbox.com"},
    "facebook": {"facebook.com", "facebookmail.com"},
    "google": {"google.com"},
    "instagram": {"instagram.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com"},
    "netflix": {"netflix.com"},
    "paypal": {"paypal.com"},
}
DANGEROUS_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".com",
    ".cpl",
    ".exe",
    ".hta",
    ".js",
    ".jse",
    ".lnk",
    ".msi",
    ".ps1",
    ".scr",
    ".vbs",
    ".vbe",
    ".wsf",
}
MACRO_EXTENSIONS = {".docm", ".dotm", ".pptm", ".potm", ".xlsm", ".xltm"}
ARCHIVE_EXTENSIONS = {".7z", ".gz", ".iso", ".rar", ".tar", ".zip"}
ACTIVE_CONTENT_EXTENSIONS = {".chm", ".htm", ".html", ".one", ".svg"}
SHORTENER_DOMAINS = {
    "bit.ly",
    "cutt.ly",
    "is.gd",
    "rebrand.ly",
    "t.co",
    "tinyurl.com",
}
COMMON_SECOND_LEVEL_SUFFIXES = {
    "co.uk",
    "com.au",
    "com.br",
    "com.tr",
    "co.jp",
    "co.nz",
    "org.uk",
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    points: int
    title: str
    evidence: str


@dataclass(frozen=True)
class UrlInfo:
    url: str
    host: str
    source: str


@dataclass(frozen=True)
class AttachmentInfo:
    filename: str
    content_type: str
    size_bytes: int


@dataclass(frozen=True)
class _HtmlSignals:
    text: str = ""
    forms: int = 0
    password_inputs: int = 0
    hidden_elements: int = 0
    images: int = 0


@dataclass
class AnalysisResult:
    source: str
    headers: dict[str, str]
    authentication: dict[str, str]
    urls: list[UrlInfo]
    attachments: list[AttachmentInfo]
    findings: list[Finding]
    heuristic_score: int
    model_prediction: ModelPrediction | None
    score: int
    verdict: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []
        self.document_text: list[str] = []
        self.forms = 0
        self.password_inputs = 0
        self.hidden_elements = 0
        self.images = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attributes = {key.lower(): value or "" for key, value in attrs}
        style = attributes.get("style", "").replace(" ", "").lower()
        if "hidden" in attributes or any(
            marker in style for marker in ("display:none", "visibility:hidden", "font-size:0")
        ):
            self.hidden_elements += 1
        if tag == "form":
            self.forms += 1
        elif tag == "input" and attributes.get("type", "").lower() == "password":
            self.password_inputs += 1
        elif tag == "img":
            self.images += 1
        if tag != "a":
            return
        self._href = attributes.get("href") or None
        self._text = []

    def handle_data(self, data: str) -> None:
        self.document_text.append(data)
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._href is not None:
            self.links.append((html.unescape(self._href), "".join(self._text).strip()))
            self._href = None
            self._text = []


def analyze_eml(path: str | Path, model: NaiveBayesModel | None = None) -> AnalysisResult:
    source = Path(path)
    with source.open("rb") as handle:
        message = BytesParser(policy=policy.default).parse(handle)
    return analyze_message(message, str(source), model=model)


def analyze_message(
    message: Message,
    source: str = "<memory>",
    model: NaiveBayesModel | None = None,
) -> AnalysisResult:
    findings: list[Finding] = []
    headers = {
        "from": str(message.get("From", "")),
        "reply_to": str(message.get("Reply-To", "")),
        "return_path": str(message.get("Return-Path", "")),
        "subject": str(message.get("Subject", "")),
        "date": str(message.get("Date", "")),
        "message_id": str(message.get("Message-ID", "")),
    }

    _analyze_sender(headers, findings)
    _analyze_brand_identity(headers, findings)
    authentication = _authentication_results(message)
    _analyze_authentication(authentication, findings)
    _analyze_subject(headers["subject"], findings)

    plain_parts, html_parts, attachments = _message_parts(message)
    urls, anchor_mismatches, html_signals = _extract_urls(plain_parts, html_parts)
    body_text = "\n".join([*plain_parts, html_signals.text])
    _analyze_body(body_text, findings)
    _analyze_html(html_signals, findings)
    _analyze_qr_lure(body_text, html_signals, attachments, findings)
    _analyze_urls(urls, anchor_mismatches, findings, sender_domain=_address_domain(headers["from"]))
    _analyze_attachments(attachments, findings)

    if html_parts and not plain_parts:
        findings.append(
            Finding("BODY_HTML_ONLY", "low", 5, "HTML-only message", "No plain-text body was found.")
        )

    findings.sort(key=lambda finding: finding.points, reverse=True)
    heuristic_score = min(100, sum(finding.points for finding in findings))
    model_prediction = model.predict_message(message) if model is not None else None
    score = heuristic_score
    if (
        model_prediction is not None
        and model_prediction.known_tokens >= 3
        and model_prediction.label == "phishing"
    ):
        model_score = round(model_prediction.phishing_probability * 100)
        score = max(heuristic_score, round(heuristic_score * 0.45 + model_score * 0.55))
    verdict = "high-risk" if score >= 50 else "suspicious" if score >= 20 else "low-risk"
    return AnalysisResult(
        source=source,
        headers=headers,
        authentication=authentication,
        urls=urls,
        attachments=attachments,
        findings=findings,
        heuristic_score=heuristic_score,
        model_prediction=model_prediction,
        score=score,
        verdict=verdict,
    )


def _normalize_text(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value.casefold())
    return "".join(character for character in decomposed if not unicodedata.combining(character))


def _address_domain(value: str) -> str:
    address = parseaddr(value)[1]
    return address.rsplit("@", 1)[-1].lower().strip(".>") if "@" in address else ""


def _base_domain(host: str) -> str:
    labels = host.lower().strip(".").split(".")
    if len(labels) < 2:
        return host
    suffix = ".".join(labels[-2:])
    return ".".join(labels[-3:]) if suffix in COMMON_SECOND_LEVEL_SUFFIXES and len(labels) >= 3 else suffix


def _share_official_brand(left_domain: str, right_domain: str) -> bool:
    return any(left_domain in domains and right_domain in domains for domains in BRAND_DOMAINS.values())


def _analyze_sender(headers: dict[str, str], findings: list[Finding]) -> None:
    sender = _address_domain(headers["from"])
    reply_to = _address_domain(headers["reply_to"])
    return_path = _address_domain(headers["return_path"])

    if not sender:
        findings.append(Finding("SENDER_MISSING", "medium", 15, "Missing sender", "From has no valid email address."))
    if sender and reply_to and _base_domain(sender) != _base_domain(reply_to):
        findings.append(
            Finding(
                "REPLY_TO_MISMATCH",
                "medium",
                20,
                "Reply-To domain mismatch",
                f"From uses {sender}, but replies go to {reply_to}.",
            )
        )
    if sender and return_path and _base_domain(sender) != _base_domain(return_path):
        findings.append(
            Finding(
                "RETURN_PATH_MISMATCH",
                "low",
                10,
                "Return-Path domain mismatch",
                f"From uses {sender}, but Return-Path uses {return_path}.",
            )
        )


def _analyze_brand_identity(headers: dict[str, str], findings: list[Finding]) -> None:
    display_name, _ = parseaddr(headers["from"])
    identity = _normalize_text(display_name)
    sender_domain = _base_domain(_address_domain(headers["from"]))
    for brand, official_domains in BRAND_DOMAINS.items():
        if brand in identity and sender_domain and sender_domain not in official_domains:
            findings.append(
                Finding(
                    "SENDER_BRAND_MISMATCH",
                    "medium",
                    18,
                    "Brand name does not match sender domain",
                    f"Display name mentions {brand}, but the sender domain is {sender_domain}.",
                )
            )
            return


def _authentication_results(message: Message) -> dict[str, str]:
    values = message.get_all("Authentication-Results", [])
    if values:
        combined = str(values[0])
        return {method.lower(): result.lower() for method, result in AUTH_PATTERN.findall(combined)}

    received_spf = message.get_all("Received-SPF", [])
    if received_spf:
        result = str(received_spf[0]).split(maxsplit=1)[0].lower().strip(";:")
        if re.fullmatch(r"[a-z_-]+", result):
            return {"spf": result}
    return {}


def _analyze_authentication(authentication: dict[str, str], findings: list[Finding]) -> None:
    points = {"spf": 15, "dkim": 20, "dmarc": 30}
    failed_states = {"fail", "softfail", "temperror", "permerror"}
    for method, result in authentication.items():
        if result in failed_states:
            findings.append(
                Finding(
                    f"AUTH_{method.upper()}_{result.upper()}",
                    "high" if method == "dmarc" else "medium",
                    points[method],
                    f"{method.upper()} authentication issue",
                    f"Authentication-Results reports {method}={result}.",
                )
            )


def _analyze_subject(subject: str, findings: list[Finding]) -> None:
    normalized = _normalize_text(subject)
    matched = sorted(term for term in URGENT_TERMS if term in normalized)
    if matched:
        findings.append(
            Finding(
                "SUBJECT_PRESSURE_LANGUAGE",
                "low",
                8,
                "Pressure language in subject",
                "Matched: " + ", ".join(matched[:3]),
            )
        )


def _analyze_body(body: str, findings: list[Finding]) -> None:
    normalized = _normalize_text(body)
    pressure = sorted(term for term in BODY_PRESSURE_TERMS if term in normalized)
    credentials = sorted(term for term in CREDENTIAL_TERMS if term in normalized)
    actions = sorted(term for term in ACTION_TERMS if term in normalized)
    financial = sorted(term for term in FINANCIAL_TERMS if term in normalized)

    if pressure:
        findings.append(
            Finding(
                "BODY_PRESSURE_LANGUAGE",
                "low",
                8,
                "Pressure language in message body",
                "Matched: " + ", ".join(pressure[:3]),
            )
        )
    if credentials and actions:
        findings.append(
            Finding(
                "BODY_CREDENTIAL_REQUEST",
                "medium",
                18,
                "Message asks for credentials or verification",
                "Credential terms: "
                + ", ".join(credentials[:3])
                + "; action terms: "
                + ", ".join(actions[:3]),
            )
        )
    if financial and actions:
        findings.append(
            Finding(
                "BODY_FINANCIAL_REQUEST",
                "medium",
                15,
                "Message pushes a financial action",
                "Financial terms: "
                + ", ".join(financial[:3])
                + "; action terms: "
                + ", ".join(actions[:3]),
            )
        )


def _analyze_html(signals: _HtmlSignals, findings: list[Finding]) -> None:
    if signals.password_inputs:
        findings.append(
            Finding(
                "HTML_PASSWORD_FORM",
                "high",
                35,
                "Password field embedded in email",
                "The HTML contains a password input. Legitimate email should not collect passwords inside the message.",
            )
        )
    elif signals.forms:
        findings.append(
            Finding(
                "HTML_FORM",
                "medium",
                20,
                "Interactive form embedded in email",
                f"The HTML contains {signals.forms} form element(s).",
            )
        )
    if signals.hidden_elements:
        findings.append(
            Finding(
                "HTML_HIDDEN_CONTENT",
                "low",
                8,
                "Hidden HTML content detected",
                f"Found {signals.hidden_elements} element(s) hidden with HTML or CSS.",
            )
        )


def _analyze_qr_lure(
    body: str,
    signals: _HtmlSignals,
    attachments: list[AttachmentInfo],
    findings: list[Finding],
) -> None:
    normalized = _normalize_text(body)
    mentions_qr = any(term in normalized for term in ("qr code", "qr kod", "scan the qr", "qr tara"))
    image_attachment = any(attachment.content_type.startswith("image/") for attachment in attachments)
    if mentions_qr and (signals.images or image_attachment):
        findings.append(
            Finding(
                "QR_CODE_LURE",
                "medium",
                18,
                "QR-code action requested",
                "The message asks the recipient to use a QR code, which can hide the destination URL.",
            )
        )


def _message_parts(message: Message) -> tuple[list[str], list[str], list[AttachmentInfo]]:
    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[AttachmentInfo] = []

    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        payload = part.get_payload(decode=True) or b""
        if filename or disposition == "attachment":
            attachments.append(
                AttachmentInfo(filename=filename or "<unnamed>", content_type=part.get_content_type(), size_bytes=len(payload))
            )
            continue
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeError):
            content = payload.decode("utf-8", errors="replace")
        if part.get_content_type() == "text/plain":
            plain_parts.append(str(content))
        else:
            html_parts.append(str(content))
    return plain_parts, html_parts, attachments


def _clean_url(value: str) -> str:
    return html.unescape(value).rstrip(".,;:!?)]}")


def _extract_urls(
    plain_parts: list[str], html_parts: list[str]
) -> tuple[list[UrlInfo], list[tuple[str, str]], _HtmlSignals]:
    collected: dict[str, UrlInfo] = {}
    mismatches: list[tuple[str, str]] = []
    html_text: list[str] = []
    forms = password_inputs = hidden_elements = images = 0

    for body in plain_parts:
        for match in URL_PATTERN.findall(body):
            url = _clean_url(match)
            collected.setdefault(url, UrlInfo(url=url, host=_url_host(url), source="plain-text"))

    for body in html_parts:
        parser = _LinkParser()
        parser.feed(body)
        html_text.extend(parser.document_text)
        forms += parser.forms
        password_inputs += parser.password_inputs
        hidden_elements += parser.hidden_elements
        images += parser.images
        for href, label in parser.links:
            if not href.lower().startswith(("http://", "https://")):
                continue
            url = _clean_url(href)
            target_host = _url_host(url)
            collected.setdefault(url, UrlInfo(url=url, host=target_host, source="html-link"))
            visible_match = URL_PATTERN.search(label)
            if visible_match:
                visible_host = _url_host(_clean_url(visible_match.group(0)))
                if visible_host and target_host and _base_domain(visible_host) != _base_domain(target_host):
                    mismatches.append((visible_host, target_host))
        for match in URL_PATTERN.findall(body):
            url = _clean_url(match)
            collected.setdefault(url, UrlInfo(url=url, host=_url_host(url), source="html-text"))
    return (
        list(collected.values()),
        mismatches,
        _HtmlSignals(
            text=" ".join(html_text),
            forms=forms,
            password_inputs=password_inputs,
            hidden_elements=hidden_elements,
            images=images,
        ),
    )


def _url_host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().strip(".")
    except ValueError:
        return ""


def _analyze_urls(
    urls: list[UrlInfo],
    mismatches: list[tuple[str, str]],
    findings: list[Finding],
    sender_domain: str = "",
) -> None:
    hosts = {item.host for item in urls if item.host}
    ip_hosts: list[str] = []
    for host in hosts:
        try:
            ipaddress.ip_address(host)
            ip_hosts.append(host)
        except ValueError:
            pass

    if ip_hosts:
        findings.append(
            Finding("URL_IP_HOST", "high", 25, "Link uses a raw IP address", "Hosts: " + ", ".join(sorted(ip_hosts)[:3]))
        )
    punycode_hosts = sorted(host for host in hosts if "xn--" in host)
    if punycode_hosts:
        findings.append(
            Finding("URL_PUNYCODE", "medium", 15, "Punycode link detected", "Hosts: " + ", ".join(punycode_hosts[:3]))
        )
    unicode_hosts = sorted(host for host in hosts if any(ord(character) > 127 for character in host))
    if unicode_hosts:
        findings.append(
            Finding(
                "URL_UNICODE_HOST",
                "medium",
                15,
                "Unicode link domain detected",
                "Hosts: " + ", ".join(unicode_hosts[:3]),
            )
        )
    shortened = sorted(host for host in hosts if host in SHORTENER_DOMAINS)
    if shortened:
        findings.append(
            Finding("URL_SHORTENER", "medium", 12, "Shortened link detected", "Hosts: " + ", ".join(shortened[:3]))
        )
    credential_urls: list[str] = []
    for item in urls:
        try:
            if urlsplit(item.url).username:
                credential_urls.append(item.host)
        except ValueError:
            continue
    if credential_urls:
        findings.append(
            Finding("URL_USERINFO", "high", 25, "Link contains user-info", "This can disguise the real destination host.")
        )
    deep_hosts = sorted(
        host
        for host in hosts
        if len(host.split(".")) >= 5 and not _is_ip_address(host)
    )
    if deep_hosts:
        findings.append(
            Finding(
                "URL_EXCESSIVE_SUBDOMAINS",
                "low",
                6,
                "Link uses many subdomains",
                "Hosts: " + ", ".join(deep_hosts[:3]),
            )
        )

    redirect_hosts: set[str] = set()
    credential_mismatches: set[str] = set()
    lookalike_hosts: set[str] = set()
    sender_base = _base_domain(sender_domain) if sender_domain else ""
    for item in urls:
        try:
            parsed = urlsplit(item.url)
        except ValueError:
            continue
        parameters = parse_qs(parsed.query, keep_blank_values=True)
        if any(
            key.casefold() in REDIRECT_PARAMETER_NAMES
            and any(unquote(value).lower().startswith(("http://", "https://")) for value in values)
            for key, values in parameters.items()
        ):
            redirect_hosts.add(item.host)

        normalized_target = _normalize_text(f"{parsed.path} {parsed.query}")
        target_requests_credentials = any(term in normalized_target for term in CREDENTIAL_URL_TERMS)
        if (
            sender_base
            and item.host
            and target_requests_credentials
            and _base_domain(item.host) != sender_base
            and not _share_official_brand(sender_base, _base_domain(item.host))
            and item.host not in SHORTENER_DOMAINS
        ):
            credential_mismatches.add(item.host)

        host_base = _base_domain(item.host)
        for brand, official_domains in BRAND_DOMAINS.items():
            if brand in item.host and host_base not in official_domains:
                lookalike_hosts.add(item.host)
                break

    if redirect_hosts:
        findings.append(
            Finding(
                "URL_NESTED_REDIRECT",
                "medium",
                12,
                "Link contains an external redirect target",
                "Hosts: " + ", ".join(sorted(redirect_hosts)[:3]),
            )
        )
    if credential_mismatches:
        findings.append(
            Finding(
                "URL_SENDER_DOMAIN_MISMATCH",
                "medium",
                15,
                "Login link does not match sender domain",
                f"Sender uses {sender_base}; credential-themed links use "
                + ", ".join(sorted(credential_mismatches)[:3])
                + ".",
            )
        )
    if lookalike_hosts:
        findings.append(
            Finding(
                "URL_BRAND_LOOKALIKE",
                "high",
                22,
                "Link may imitate a known brand",
                "Hosts: " + ", ".join(sorted(lookalike_hosts)[:3]),
            )
        )
    if mismatches:
        visible, target = mismatches[0]
        findings.append(
            Finding(
                "URL_LABEL_MISMATCH",
                "high",
                30,
                "Visible link and destination differ",
                f"Displayed {visible}, but opens {target}.",
            )
        )


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _analyze_attachments(attachments: list[AttachmentInfo], findings: list[Finding]) -> None:
    for attachment in attachments:
        suffixes = [suffix.lower() for suffix in Path(attachment.filename).suffixes]
        extension = suffixes[-1] if suffixes else ""
        if extension in DANGEROUS_EXTENSIONS:
            findings.append(
                Finding(
                    "ATTACHMENT_EXECUTABLE",
                    "high",
                    35,
                    "Executable attachment",
                    f"Attachment {attachment.filename} uses {extension}.",
                )
            )
        elif extension in MACRO_EXTENSIONS:
            findings.append(
                Finding(
                    "ATTACHMENT_MACRO",
                    "high",
                    25,
                    "Macro-enabled attachment",
                    f"Attachment {attachment.filename} can contain macros.",
                )
            )
        elif extension in ARCHIVE_EXTENSIONS:
            findings.append(
                Finding(
                    "ATTACHMENT_ARCHIVE",
                    "low",
                    8,
                    "Archive attachment",
                    f"Attachment {attachment.filename} may conceal other files.",
                )
            )
        elif extension in ACTIVE_CONTENT_EXTENSIONS:
            findings.append(
                Finding(
                    "ATTACHMENT_ACTIVE_CONTENT",
                    "medium",
                    20,
                    "Active-content attachment",
                    f"Attachment {attachment.filename} can contain interactive or executable content.",
                )
            )
        if len(suffixes) >= 2 and suffixes[-2] in {".doc", ".jpg", ".pdf", ".png", ".txt", ".xlsx"}:
            findings.append(
                Finding(
                    "ATTACHMENT_DOUBLE_EXTENSION",
                    "medium",
                    15,
                    "Double-extension attachment",
                    f"Attachment {attachment.filename} may disguise its real file type.",
                )
            )
        if any(character in attachment.filename for character in "\u202a\u202b\u202d\u202e\u2066\u2067\u2068\u2069"):
            findings.append(
                Finding(
                    "ATTACHMENT_BIDI_NAME",
                    "high",
                    25,
                    "Attachment name uses bidirectional controls",
                    "The filename contains invisible direction controls that can disguise its extension.",
                )
            )
