from __future__ import annotations

import json
import math
import random
import re
import unicodedata
from collections import Counter
from dataclasses import asdict, dataclass
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit


MODEL_FORMAT_VERSION = 1
LABELS = ("legitimate", "phishing")
TOKEN_PATTERN = re.compile(r"[a-z0-9]{2,}")
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
MAX_MESSAGE_TOKENS = 50_000
MAX_TOKEN_FREQUENCY = 20


class ModelError(ValueError):
    """Raised when a model or training dataset is invalid."""


@dataclass(frozen=True)
class ModelPrediction:
    phishing_probability: float
    label: str
    known_tokens: int


@dataclass(frozen=True)
class ValidationMetrics:
    samples: int
    accuracy: float
    precision: float
    recall: float
    f1: float
    true_positive: int
    true_negative: int
    false_positive: int
    false_negative: int


@dataclass(frozen=True)
class TrainingReport:
    training_documents: dict[str, int]
    validation_documents: dict[str, int]
    vocabulary_size: int
    validation: ValidationMetrics | None
    warnings: list[str]


@dataclass
class NaiveBayesModel:
    document_counts: dict[str, int]
    token_counts: dict[str, dict[str, int]]
    total_tokens: dict[str, int]
    vocabulary: list[str]
    alpha: float = 1.0
    format_version: int = MODEL_FORMAT_VERSION

    def predict_message(self, message: Message) -> ModelPrediction:
        features = extract_features(message)
        vocabulary = set(self.vocabulary)
        matched = {token: count for token, count in features.items() if token in vocabulary}
        total_documents = sum(self.document_counts.values())
        vocabulary_size = max(1, len(vocabulary))
        log_probabilities: dict[str, float] = {}

        for label in LABELS:
            prior = (self.document_counts[label] + self.alpha) / (
                total_documents + self.alpha * len(LABELS)
            )
            denominator = self.total_tokens[label] + self.alpha * vocabulary_size
            score = math.log(prior)
            label_counts = self.token_counts[label]
            for token, count in matched.items():
                probability = (label_counts.get(token, 0) + self.alpha) / denominator
                score += count * math.log(probability)
            log_probabilities[label] = score

        difference = max(
            -60.0,
            min(60.0, log_probabilities["legitimate"] - log_probabilities["phishing"]),
        )
        phishing_probability = 1.0 / (1.0 + math.exp(difference))
        if len(matched) < 3:
            label = "insufficient-data"
        elif phishing_probability >= 0.65:
            label = "phishing"
        elif phishing_probability <= 0.35:
            label = "legitimate"
        else:
            label = "uncertain"
        return ModelPrediction(
            phishing_probability=round(phishing_probability, 6),
            label=label,
            known_tokens=len(matched),
        )

    def save(self, path: str | Path) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(asdict(self), ensure_ascii=False, separators=(",", ":")), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> NaiveBayesModel:
        source = Path(path)
        try:
            payload = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ModelError(f"could not read model {source}: {error}") from error

        if payload.get("format_version") != MODEL_FORMAT_VERSION:
            raise ModelError(
                f"unsupported model format: {payload.get('format_version')!r}; "
                f"expected {MODEL_FORMAT_VERSION}"
            )
        try:
            model = cls(
                document_counts={label: int(payload["document_counts"][label]) for label in LABELS},
                token_counts={
                    label: {str(token): int(count) for token, count in payload["token_counts"][label].items()}
                    for label in LABELS
                },
                total_tokens={label: int(payload["total_tokens"][label]) for label in LABELS},
                vocabulary=[str(token) for token in payload["vocabulary"]],
                alpha=float(payload.get("alpha", 1.0)),
                format_version=int(payload["format_version"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ModelError(f"invalid model structure in {source}: {error}") from error
        if not model.vocabulary or any(count < 1 for count in model.document_counts.values()):
            raise ModelError(f"model {source} has no usable training data")
        return model


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def _normalize(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value.casefold())
    return "".join(character for character in decomposed if not unicodedata.combining(character))


def _tokens(value: str, prefix: str) -> list[str]:
    words = TOKEN_PATTERN.findall(_normalize(value))
    unigrams = [f"{prefix}:{word}" for word in words]
    bigrams = [f"{prefix}2:{left}_{right}" for left, right in zip(words, words[1:])]
    return unigrams + bigrams


def _character_ngrams(value: str, prefix: str, limit: int = 300) -> list[str]:
    compact = re.sub(r"[^a-z0-9]+", "", _normalize(value))[:limit]
    return [
        f"{prefix}{size}:{compact[index:index + size]}"
        for size in (3, 4)
        for index in range(max(0, len(compact) - size + 1))
    ]


def _address_domain(value: str) -> str:
    address = parseaddr(value)[1]
    return address.rsplit("@", 1)[-1].lower().strip(".>") if "@" in address else ""


def _part_text(part: Message) -> str:
    payload = part.get_payload(decode=True) or b""
    try:
        return str(part.get_content())
    except (LookupError, UnicodeError):
        return payload.decode("utf-8", errors="replace")


def extract_features(message: Message) -> Counter[str]:
    features: Counter[str] = Counter()
    subject = str(message.get("Subject", ""))
    sender = str(message.get("From", ""))
    reply_to = str(message.get("Reply-To", ""))
    authentication = " ".join(str(value) for value in message.get_all("Authentication-Results", []))
    features.update(_tokens(subject, "subject"))
    features.update(_character_ngrams(subject, "subject-char"))
    features.update(_tokens(sender, "sender"))
    features.update(_tokens(reply_to, "reply"))
    features.update(_tokens(str(message.get("To", "")), "recipient"))
    features.update(_tokens(authentication, "auth"))

    body_tokens: list[str] = []
    url_sources: list[str] = []
    has_html = False
    has_form = False
    has_password_input = False
    has_attachment = False
    attachment_count = 0
    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment":
            has_attachment = True
            attachment_count += 1
            if filename:
                features.update(_tokens(filename, "attachment"))
                suffix = Path(filename).suffix.lower().lstrip(".")
                if suffix:
                    features[f"attachment-ext:{suffix}"] += 1
            continue
        content_type = part.get_content_type()
        if content_type == "text/plain":
            content = _part_text(part)
            body_tokens.extend(_tokens(content, "body"))
            url_sources.append(content)
        elif content_type == "text/html":
            has_html = True
            content = _part_text(part)
            parser = _TextExtractor()
            parser.feed(content)
            body_tokens.extend(_tokens(" ".join(parser.parts), "body"))
            url_sources.append(content)
            normalized_html = content.casefold().replace(" ", "")
            has_form = has_form or "<form" in normalized_html
            has_password_input = has_password_input or any(
                marker in normalized_html for marker in ('type="password"', "type='password'")
            )

    features.update(body_tokens[:MAX_MESSAGE_TOKENS])
    link_count = 0
    for source in url_sources:
        for raw_url in URL_PATTERN.findall(source):
            link_count += 1
            try:
                parsed = urlsplit(raw_url.rstrip(".,;:!?)]}"))
            except ValueError:
                features["url:malformed"] += 1
                continue
            host = (parsed.hostname or "").lower().strip(".")
            if host:
                features.update(_tokens(host, "urlhost"))
                features.update(_character_ngrams(host, "urlhost-char", limit=120))
                labels = host.split(".")
                features[f"url:tld:{labels[-1]}"] += 1
                if len(labels) >= 5:
                    features["url:deep-host"] += 1
                if "xn--" in host:
                    features["url:punycode"] += 1
            features.update(_tokens(parsed.path, "urlpath"))
            if parsed.username:
                features["url:user-info"] += 1
            if parsed.scheme.lower() == "http":
                features["url:plain-http"] += 1

    if has_html:
        features["structure:html"] += 1
    if has_form:
        features["structure:form"] += 1
    if has_password_input:
        features["structure:password-input"] += 1
    if has_attachment:
        features["structure:attachment"] += 1
        features[f"structure:attachment-count:{min(attachment_count, 5)}"] += 1
    if message.get("Reply-To"):
        features["structure:reply-to"] += 1
    sender_domain = _address_domain(sender)
    reply_domain = _address_domain(reply_to)
    if sender_domain and reply_domain and sender_domain != reply_domain:
        features["structure:sender-reply-mismatch"] += 1
    normalized_authentication = _normalize(authentication)
    for method in ("spf", "dkim", "dmarc"):
        if re.search(rf"\b{method}\s*=\s*(?:fail|softfail|permerror|temperror)\b", normalized_authentication):
            features[f"auth-failure:{method}"] += 1
    if link_count:
        link_bucket = "many" if link_count >= 6 else "few" if link_count >= 2 else "one"
        features[f"structure:links:{link_bucket}"] += 1
    for token in list(features):
        features[token] = min(features[token], MAX_TOKEN_FREQUENCY)
    return features


def load_dataset(path: str | Path) -> dict[str, list[tuple[str, Message]]]:
    root = Path(path)
    if not root.is_dir():
        raise ModelError(f"training directory not found: {root}")

    dataset: dict[str, list[tuple[str, Message]]] = {label: [] for label in LABELS}
    for label in LABELS:
        label_directory = root / label
        if not label_directory.is_dir():
            raise ModelError(f"missing training directory: {label_directory}")
        files = sorted(
            (item for item in label_directory.rglob("*") if item.is_file() and item.suffix.lower() == ".eml"),
            key=lambda item: str(item).casefold(),
        )
        for file_path in files:
            try:
                with file_path.open("rb") as handle:
                    message = BytesParser(policy=policy.default).parse(handle)
            except OSError as error:
                raise ModelError(f"could not read training message {file_path}: {error}") from error
            dataset[label].append((str(file_path), message))
        if not dataset[label]:
            raise ModelError(f"no .eml files found in {label_directory}")
    return dataset


def _split_dataset(
    dataset: dict[str, list[tuple[str, Message]]], validation_split: float, seed: int
) -> tuple[list[tuple[str, Message]], list[tuple[str, Message]]]:
    training: list[tuple[str, Message]] = []
    validation: list[tuple[str, Message]] = []
    randomizer = random.Random(seed)
    for label in LABELS:
        samples = list(dataset[label])
        randomizer.shuffle(samples)
        validation_count = 0
        if validation_split > 0 and len(samples) >= 3:
            validation_count = min(len(samples) - 1, max(1, round(len(samples) * validation_split)))
        validation.extend((label, message) for _, message in samples[:validation_count])
        training.extend((label, message) for _, message in samples[validation_count:])
    return training, validation


def _fit(
    samples: Iterable[tuple[str, Message]], min_document_frequency: int, max_features: int
) -> NaiveBayesModel:
    prepared: list[tuple[str, Counter[str]]] = []
    document_frequency: Counter[str] = Counter()
    document_counts = {label: 0 for label in LABELS}

    for label, message in samples:
        features = extract_features(message)
        prepared.append((label, features))
        document_counts[label] += 1
        document_frequency.update(features.keys())

    if any(document_counts[label] == 0 for label in LABELS):
        raise ModelError("both labels need at least one training message")
    candidates = [
        token for token, frequency in document_frequency.items() if frequency >= min_document_frequency
    ]
    candidates.sort(key=lambda token: (-document_frequency[token], token))
    vocabulary = candidates[:max_features]
    if not vocabulary:
        raise ModelError("no model features remain; lower --min-df or add more messages")

    vocabulary_set = set(vocabulary)
    token_counts: dict[str, Counter[str]] = {label: Counter() for label in LABELS}
    for label, features in prepared:
        token_counts[label].update(
            {token: count for token, count in features.items() if token in vocabulary_set}
        )
    totals = {label: sum(token_counts[label].values()) for label in LABELS}
    return NaiveBayesModel(
        document_counts=document_counts,
        token_counts={label: dict(token_counts[label]) for label in LABELS},
        total_tokens=totals,
        vocabulary=vocabulary,
    )


def _evaluate(model: NaiveBayesModel, samples: list[tuple[str, Message]]) -> ValidationMetrics | None:
    if not samples:
        return None
    true_positive = true_negative = false_positive = false_negative = 0
    for expected, message in samples:
        predicted = "phishing" if model.predict_message(message).phishing_probability >= 0.65 else "legitimate"
        if expected == "phishing" and predicted == "phishing":
            true_positive += 1
        elif expected == "legitimate" and predicted == "legitimate":
            true_negative += 1
        elif expected == "legitimate":
            false_positive += 1
        else:
            false_negative += 1

    total = len(samples)
    precision_denominator = true_positive + false_positive
    recall_denominator = true_positive + false_negative
    precision = true_positive / precision_denominator if precision_denominator else 0.0
    recall = true_positive / recall_denominator if recall_denominator else 0.0
    return ValidationMetrics(
        samples=total,
        accuracy=(true_positive + true_negative) / total,
        precision=precision,
        recall=recall,
        f1=2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        true_positive=true_positive,
        true_negative=true_negative,
        false_positive=false_positive,
        false_negative=false_negative,
    )


def train_from_directory(
    path: str | Path,
    *,
    validation_split: float = 0.2,
    seed: int = 1337,
    min_document_frequency: int = 1,
    max_features: int = 20_000,
) -> tuple[NaiveBayesModel, TrainingReport]:
    if not 0.0 <= validation_split < 1.0:
        raise ModelError("validation split must be at least 0 and less than 1")
    if min_document_frequency < 1:
        raise ModelError("minimum document frequency must be at least 1")
    if max_features < 10:
        raise ModelError("maximum features must be at least 10")

    dataset = load_dataset(path)
    training, validation = _split_dataset(dataset, validation_split, seed)
    model = _fit(training, min_document_frequency, max_features)
    metrics = _evaluate(model, validation)
    warnings: list[str] = []
    if any(len(dataset[label]) < 50 for label in LABELS):
        warnings.append(
            "This is a small dataset. Use at least 50 varied messages per label for an initial experiment."
        )
    if metrics is None:
        warnings.append("No validation set was created; add at least 3 messages to each label.")
    elif metrics.samples < 20:
        warnings.append("Validation has fewer than 20 messages, so its metrics are unstable.")

    training_documents = Counter(label for label, _ in training)
    validation_documents = Counter(label for label, _ in validation)
    return model, TrainingReport(
        training_documents={label: training_documents[label] for label in LABELS},
        validation_documents={label: validation_documents[label] for label in LABELS},
        vocabulary_size=len(model.vocabulary),
        validation=metrics,
        warnings=warnings,
    )
