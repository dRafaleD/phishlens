# PhishLens

Explainable, local-first phishing triage for exported emails and read-only IMAP mailbox scans.

PhishLens helps analysts and curious users review suspicious messages without opening links or attachments. It combines transparent detection rules with an optional locally trained Naive Bayes model, then explains which signals influenced the result.

> **Important:** PhishLens is a triage aid, not a security verdict. Never interact with a suspicious message based only on this tool's output. Verify unexpected requests through a trusted, independent channel.

## Highlights

- Analyze individual `.eml` files from the command line or the dark terminal-style desktop GUI.
- Scan complete folders, optionally including subfolders, and rank messages by risk.
- Export text, JSON, or Excel-friendly CSV reports.
- Inspect sender-header inconsistencies, SPF/DKIM/DMARC results, suspicious language, links, HTML, and attachments.
- Detect raw-IP links, redirects, URL/domain mismatches, lookalike domains, risky URL structures, deceptive filenames, macros, archives, forms, hidden HTML, and QR-code lures.
- Train an optional local model from labeled phishing and legitimate messages.
- Scan Gmail, Outlook, or a custom IMAP server over TLS in read-only mode without marking messages as read.
- Keep email analysis, model training, and model inference on the local machine.

## Privacy and Safety

PhishLens does not visit URLs, execute attachments, or upload email content. Local `.eml` analysis and model training work offline.

Mailbox mode is the exception: it connects to the IMAP server only when explicitly requested. It uses TLS, opens folders read-only, and fetches messages with `BODY.PEEK[]`. Credentials and tokens are read from environment variables, never command-line arguments.

The optional model stores aggregate token counts and vocabulary. These may still contain sensitive words, so personal datasets and generated model files should remain private. They are ignored by Git by default when using the included ignore rules.

## Requirements

- Python 3.11 or newer
- Windows, macOS, or Linux for the CLI
- Tk support for the desktop GUI
- No runtime dependencies for the core application

## Installation

```powershell
git clone https://github.com/dRafaleD/phishlens.git
cd phishlens
py -m pip install -e .
phishlens --version
```

On systems where `py` is unavailable, use `python` instead.

## Quick Start

Analyze an exported email:

```powershell
phishlens analyze "C:\Users\you\Desktop\suspicious.eml"
```

Launch the desktop interface:

```powershell
phishlens gui
```

The GUI supports single-message analysis, folder scans, model loading, local training, evidence inspection, report saving, and CSV export.

The original short form remains supported:

```powershell
phishlens "C:\Users\you\Desktop\suspicious.eml"
```

## Folder Scans and Reports

Scan every `.eml` file in a directory:

```powershell
phishlens scan "C:\Users\you\Desktop\mail-samples"
```

Include subfolders and save a readable text report:

```powershell
phishlens scan "C:\Users\you\Desktop\mail-samples" --recursive --output folder-report.txt
```

Save machine-readable JSON for automation or later processing:

```powershell
phishlens scan "C:\Users\you\Desktop\mail-samples" --recursive --json --output folder-report.json
```

The command exits with code `1` when at least one message is high-risk, which makes it suitable for simple scripts and CI checks. Exit code `2` indicates an operational error.

## Local Model Training

Training is supervised. Place exported `.eml` files into this structure:

```text
training-data/
|-- phishing/
|   |-- known-phish-001.eml
|   `-- known-phish-002.eml
`-- legitimate/
    |-- normal-mail-001.eml
    `-- normal-mail-002.eml
```

Train and use a model:

```powershell
phishlens train training-data --output phishlens-model.json
phishlens analyze "C:\Users\you\Desktop\suspicious.eml" --model phishlens-model.json
phishlens scan "C:\Users\you\Desktop\mail-samples" --recursive --model phishlens-model.json
```

The included example dataset only demonstrates the workflow. For meaningful evaluation, use at least 50 varied messages per label, keep classes reasonably balanced, remove duplicates, and reserve a separate final test set that is never used during training.

## Mailbox Mode

Mailbox mode supports Gmail, Outlook, and custom IMAP servers. Provider authentication and OAuth token refresh are intentionally not automated.

Example with a Gmail app password:

```powershell
$env:PHISHLENS_IMAP_USERNAME = "you@gmail.com"
$env:PHISHLENS_IMAP_PASSWORD = "your-app-password"
phishlens mailbox --provider gmail --auth password --limit 10 --unread-only
Remove-Item Env:PHISHLENS_IMAP_PASSWORD
```

Example with a short-lived Outlook OAuth2 access token:

```powershell
$env:PHISHLENS_IMAP_USERNAME = "you@outlook.com"
$env:PHISHLENS_OAUTH_TOKEN = "your-access-token"
phishlens mailbox --provider outlook --auth oauth2 --limit 10 --unread-only
Remove-Item Env:PHISHLENS_OAUTH_TOKEN
```

Never commit passwords, tokens, private emails, training datasets, or personal model files.

## How Scoring Works

The rule engine produces an explainable heuristic score from 0 to 100. Without a model, this is the final score. When a model recognizes enough features and predicts phishing with sufficient confidence, PhishLens blends the model signal with the heuristic score. A model cannot suppress a high-confidence rule-based warning.

Current verdict thresholds are:

- `low-risk`: below 20
- `suspicious`: 20 to 49
- `high-risk`: 50 or higher

These labels describe triage priority, not proof of intent.

## Development

Run the test suite from the repository root:

```powershell
$env:PYTHONPATH = "src"
py -m unittest discover -s tests -v
```

The project uses a `src/` layout and keeps the core implementation dependency-free. Contributions should include focused tests and avoid sending email content to external services.

## Project Status

PhishLens is an early-stage defensive security project. Detection rules are intentionally conservative and can produce false positives or miss novel attacks. Treat results as investigation leads and keep human verification in the loop.

## License

MIT License. See [LICENSE](LICENSE).
