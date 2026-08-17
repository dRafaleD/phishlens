from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .analyzer import AnalysisResult, analyze_eml, analyze_message
from .classifier import ModelError, NaiveBayesModel, train_from_directory
from .gui import GuiError, launch_gui
from .mailbox import MailboxError, fetch_messages
from .reporting import (
    render_batch_json,
    render_batch_text,
    render_json,
    render_text,
    render_training_json,
    render_training_report,
)


COMMANDS = {"analyze", "scan", "train", "mailbox", "gui"}


def _add_output_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--model", type=Path, help="trained JSON model created by 'phishlens train'")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishlens",
        description="Analyze email locally with explainable rules and an optional trained model.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="analyze one .eml file")
    analyze_parser.add_argument("eml_file", type=Path, help="path to the .eml file")
    _add_output_options(analyze_parser)

    scan_parser = subparsers.add_parser("scan", help="analyze all .eml files in a directory")
    scan_parser.add_argument("directory", type=Path, help="directory containing .eml files")
    scan_parser.add_argument("-r", "--recursive", action="store_true", help="include subdirectories")
    _add_output_options(scan_parser)

    train_parser = subparsers.add_parser("train", help="train a local model from labeled .eml files")
    train_parser.add_argument(
        "dataset",
        type=Path,
        help="directory containing phishing/ and legitimate/ subdirectories",
    )
    train_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("phishlens-model.json"),
        help="model output path (default: phishlens-model.json)",
    )
    train_parser.add_argument(
        "--validation-split",
        type=float,
        default=0.2,
        help="fraction reserved for validation (default: 0.2)",
    )
    train_parser.add_argument("--seed", type=int, default=1337, help="repeatable split seed")
    train_parser.add_argument("--min-df", type=int, default=1, help="minimum message frequency for a feature")
    train_parser.add_argument("--max-features", type=int, default=20_000, help="maximum model features")
    train_parser.add_argument("--json", action="store_true", help="print machine-readable JSON")

    mailbox_parser = subparsers.add_parser(
        "mailbox",
        help="read recent Gmail, Outlook, or custom IMAP messages without marking them read",
    )
    mailbox_parser.add_argument("--provider", choices=("gmail", "outlook", "custom"), required=True)
    mailbox_parser.add_argument(
        "--username",
        help="mailbox address (or set PHISHLENS_IMAP_USERNAME)",
    )
    mailbox_parser.add_argument("--auth", choices=("password", "oauth2"), required=True)
    mailbox_parser.add_argument("--folder", default="INBOX", help="mailbox folder (default: INBOX)")
    mailbox_parser.add_argument("--limit", type=int, default=10, help="newest messages to scan, 1-100")
    mailbox_parser.add_argument("--unread-only", action="store_true", help="scan only unread messages")
    mailbox_parser.add_argument("--host", help="custom IMAP host")
    mailbox_parser.add_argument("--port", type=int, help="custom IMAP TLS port")
    _add_output_options(mailbox_parser)

    gui_parser = subparsers.add_parser("gui", help="launch the desktop interface")
    gui_parser.add_argument("--model", type=Path, help="preload a trained JSON model")
    return parser


def _load_model(path: Path | None) -> NaiveBayesModel | None:
    if path is None:
        return None
    return NaiveBayesModel.load(path)


def _print_error(message: str) -> None:
    print(f"phishlens: {message}", file=sys.stderr)


def _result_exit_code(results: list[AnalysisResult]) -> int:
    return 1 if any(result.verdict == "high-risk" for result in results) else 0


def _run_analyze(args: argparse.Namespace) -> int:
    if not args.eml_file.is_file():
        _print_error(f"file not found: {args.eml_file}")
        return 2
    try:
        model = _load_model(args.model)
        result = analyze_eml(args.eml_file, model=model)
    except (OSError, ValueError, ModelError) as error:
        _print_error(f"could not analyze file: {error}")
        return 2
    print(render_json(result) if args.json else render_text(result))
    return _result_exit_code([result])


def _eml_files(directory: Path, recursive: bool) -> list[Path]:
    iterator = directory.rglob("*") if recursive else directory.iterdir()
    return sorted(
        (item for item in iterator if item.is_file() and item.suffix.lower() == ".eml"),
        key=lambda item: str(item).casefold(),
    )


def _run_scan(args: argparse.Namespace) -> int:
    if not args.directory.is_dir():
        _print_error(f"directory not found: {args.directory}")
        return 2
    try:
        model = _load_model(args.model)
        files = _eml_files(args.directory, args.recursive)
    except (OSError, ModelError) as error:
        _print_error(f"could not start scan: {error}")
        return 2
    if not files:
        _print_error(f"no .eml files found in {args.directory}")
        return 2

    results: list[AnalysisResult] = []
    for file_path in files:
        try:
            results.append(analyze_eml(file_path, model=model))
        except (OSError, ValueError) as error:
            _print_error(f"skipped {file_path}: {error}")
    if not results:
        return 2
    print(render_batch_json(results) if args.json else render_batch_text(results))
    return _result_exit_code(results)


def _run_train(args: argparse.Namespace) -> int:
    try:
        model, report = train_from_directory(
            args.dataset,
            validation_split=args.validation_split,
            seed=args.seed,
            min_document_frequency=args.min_df,
            max_features=args.max_features,
        )
        model.save(args.output)
    except (OSError, ModelError) as error:
        _print_error(f"training failed: {error}")
        return 2
    print(
        render_training_json(report, str(args.output))
        if args.json
        else render_training_report(report, str(args.output))
    )
    return 0


def _run_mailbox(args: argparse.Namespace) -> int:
    username = args.username or os.environ.get("PHISHLENS_IMAP_USERNAME", "")
    secret_name = "PHISHLENS_OAUTH_TOKEN" if args.auth == "oauth2" else "PHISHLENS_IMAP_PASSWORD"
    secret = os.environ.get(secret_name, "")
    if not username:
        _print_error("missing mailbox username; use --username or PHISHLENS_IMAP_USERNAME")
        return 2
    if not secret:
        _print_error(f"missing secret; set the {secret_name} environment variable")
        return 2

    try:
        model = _load_model(args.model)
        mailbox_messages = fetch_messages(
            provider=args.provider,
            username=username,
            secret=secret,
            auth=args.auth,
            folder=args.folder,
            limit=args.limit,
            unread_only=args.unread_only,
            host=args.host,
            port=args.port,
        )
        results = [
            analyze_message(item.message, source=item.source, model=model)
            for item in mailbox_messages
        ]
    except (MailboxError, ModelError, OSError, ValueError) as error:
        _print_error(str(error))
        return 2
    if not results:
        print("No matching messages found.")
        return 0
    title = f"PhishLens {args.provider} mailbox scan"
    print(render_batch_json(results) if args.json else render_batch_text(results, title=title))
    return _result_exit_code(results)


def _run_gui(args: argparse.Namespace) -> int:
    try:
        launch_gui(initial_model_path=args.model)
    except (GuiError, ModelError, OSError) as error:
        _print_error(str(error))
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    raw_arguments = list(sys.argv[1:] if argv is None else argv)
    if raw_arguments and raw_arguments[0] not in COMMANDS and not raw_arguments[0].startswith("-"):
        raw_arguments.insert(0, "analyze")
    parser = build_parser()
    args = parser.parse_args(raw_arguments)
    handlers = {
        "analyze": _run_analyze,
        "scan": _run_scan,
        "train": _run_train,
        "mailbox": _run_mailbox,
        "gui": _run_gui,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
