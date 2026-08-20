from __future__ import annotations

import json
import re
from csv import DictWriter
from dataclasses import asdict
from io import StringIO
from typing import Any

from .analyzer import AnalysisResult
from .classifier import TrainingReport


CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def defang(value: str) -> str:
    return value.replace("https://", "hxxps://").replace("http://", "hxxp://").replace(".", "[.]")


def terminal_safe(value: object, limit: int = 240) -> str:
    cleaned = CONTROL_CHARACTERS.sub(" ", str(value))
    cleaned = " ".join(cleaned.split())
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 3] + "..."


def render_text(result: AnalysisResult) -> str:
    lines = [
        "PhishLens analysis",
        "=" * 18,
        f"Source:    {terminal_safe(result.source)}",
        f"Subject:   {terminal_safe(result.headers['subject'] or '<missing>')}",
        f"From:      {terminal_safe(result.headers['from'] or '<missing>')}",
        f"Heuristic: {result.heuristic_score}/100",
        f"Score:     {result.score}/100",
        f"Verdict:   {result.verdict}",
        "",
        "Findings",
        "--------",
    ]
    if result.model_prediction is None:
        lines.insert(7, "ML model:  not loaded")
    else:
        prediction = result.model_prediction
        lines.insert(
            7,
            "ML model:  "
            f"{prediction.phishing_probability:.1%} phishing | "
            f"{prediction.label} | {prediction.known_tokens} known features",
        )
    lines.extend(
        [
            "Header checks: " + _header_summary(result),
            "Decision: " + _decision_summary(result),
            "Next step: " + _next_step(result),
        ]
    )
    if not result.findings:
        lines.append("No heuristic warning was triggered.")
    for finding in result.findings:
        lines.append(f"[{finding.severity.upper():6}] +{finding.points:02} {finding.title} ({finding.rule_id})")
        lines.append(f"         {terminal_safe(finding.evidence)}")

    lines.extend(["", f"Links ({len(result.urls)})", "--------"])
    if not result.urls:
        lines.append("No HTTP(S) links found.")
    for item in result.urls:
        lines.append(f"- {terminal_safe(defang(item.url), limit=500)} [{item.source}]")

    lines.extend(["", f"Attachments ({len(result.attachments)})", "-------------"])
    if not result.attachments:
        lines.append("No attachments found.")
    for attachment in result.attachments:
        lines.append(
            f"- {terminal_safe(attachment.filename)} | "
            f"{terminal_safe(attachment.content_type)} | {attachment.size_bytes} bytes"
        )

    lines.extend(
        [
            "",
            "Note: This is a triage result, not proof that a message is safe or malicious.",
        ]
    )
    return "\n".join(lines)


def _header_summary(result: AnalysisResult) -> str:
    if not result.authentication:
        return "no SPF/DKIM/DMARC result was present in the exported message."
    return ", ".join(f"{method.upper()}={state}" for method, state in sorted(result.authentication.items()))


def _decision_summary(result: AnalysisResult) -> str:
    if not result.findings:
        return "No rule-based warning was triggered."
    leading = ", ".join(finding.title for finding in result.findings[:2])
    return f"{len(result.findings)} signal(s), led by {leading}."


def _next_step(result: AnalysisResult) -> str:
    if result.verdict == "high-risk":
        return "Do not interact with the message; verify through a known, independent contact channel."
    if result.verdict == "suspicious":
        return "Verify the sender and destination independently before responding, opening links, or downloading files."
    return "No high-risk signal was found. Still verify unexpected requests through an independent channel."


def render_json(result: AnalysisResult, pretty: bool = True) -> str:
    payload: dict[str, Any] = result.to_dict()
    return json.dumps(payload, indent=2 if pretty else None, ensure_ascii=False)


def render_batch_text(results: list[AnalysisResult], title: str = "PhishLens batch scan") -> str:
    counts = {
        verdict: sum(result.verdict == verdict for result in results)
        for verdict in ("high-risk", "suspicious", "low-risk")
    }
    lines = [
        title,
        "=" * len(title),
        f"Messages: {len(results)} | high-risk: {counts['high-risk']} | "
        f"suspicious: {counts['suspicious']} | low-risk: {counts['low-risk']}",
        "",
    ]
    for result in sorted(results, key=lambda item: (-item.score, item.source.casefold())):
        subject = terminal_safe(result.headers["subject"] or "<missing>", limit=70)
        lines.append(
            f"[{result.verdict.upper():10}] {result.score:3}/100 | {subject} | {terminal_safe(result.source)}"
        )
    lines.extend(["", "Run 'phishlens analyze <file> --model <model>' for full findings."])
    return "\n".join(lines)


def render_batch_json(results: list[AnalysisResult], pretty: bool = True) -> str:
    payload = {
        "summary": {
            "messages": len(results),
            "high_risk": sum(result.verdict == "high-risk" for result in results),
            "suspicious": sum(result.verdict == "suspicious" for result in results),
            "low_risk": sum(result.verdict == "low-risk" for result in results),
        },
        "results": [result.to_dict() for result in results],
    }
    return json.dumps(payload, indent=2 if pretty else None, ensure_ascii=False)


def render_batch_csv(results: list[AnalysisResult]) -> str:
    """Return a spreadsheet-friendly, one-row-per-message folder scan report."""
    output = StringIO(newline="")
    columns = (
        "verdict",
        "score",
        "heuristic_score",
        "subject",
        "from",
        "source",
        "finding_count",
        "findings",
    )
    writer = DictWriter(output, fieldnames=columns)
    writer.writeheader()
    for result in sorted(results, key=lambda item: (-item.score, item.source.casefold())):
        writer.writerow(
            {
                "verdict": result.verdict,
                "score": result.score,
                "heuristic_score": result.heuristic_score,
                "subject": result.headers["subject"] or "",
                "from": result.headers["from"] or "",
                "source": result.source,
                "finding_count": len(result.findings),
                "findings": "; ".join(finding.title for finding in result.findings),
            }
        )
    return output.getvalue()


def render_training_report(report: TrainingReport, model_path: str) -> str:
    lines = [
        "PhishLens model trained",
        "=======================",
        f"Model: {terminal_safe(model_path)}",
        "Training: "
        f"{report.training_documents['phishing']} phishing + "
        f"{report.training_documents['legitimate']} legitimate",
        f"Vocabulary: {report.vocabulary_size} features",
    ]
    if report.validation is not None:
        metrics = report.validation
        lines.extend(
            [
                "Validation: "
                f"{metrics.samples} messages | accuracy {metrics.accuracy:.1%} | "
                f"precision {metrics.precision:.1%} | recall {metrics.recall:.1%} | "
                f"F1 {metrics.f1:.1%}",
                "Confusion: "
                f"TP={metrics.true_positive} TN={metrics.true_negative} "
                f"FP={metrics.false_positive} FN={metrics.false_negative}",
            ]
        )
    for warning in report.warnings:
        lines.append(f"Warning: {terminal_safe(warning)}")
    return "\n".join(lines)


def render_training_json(report: TrainingReport, model_path: str) -> str:
    return json.dumps(
        {"model": model_path, "report": asdict(report)},
        indent=2,
        ensure_ascii=False,
    )
