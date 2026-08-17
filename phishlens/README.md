# PhishLens

PhishLens is an explainable phishing-triage tool for `.eml` files and IMAP mailboxes. It combines transparent security rules with an optional local Naive Bayes model trained on your labeled email. File analysis and model training stay offline; mailbox access happens only when the `mailbox` command is used.

PhishLens never opens attachments, visits links, or uploads email content. A result is triage guidance, not proof that a message is safe or malicious.

## What it checks

- `From`, `Reply-To`, and `Return-Path` domain mismatches
- SPF, DKIM, and DMARC failures from message headers
- pressure, credential, and financial requests in English and Turkish subjects and bodies
- raw-IP, Unicode/Punycode, shortened, redirected, misleading, lookalike, and user-info URLs
- sender/brand identity and credential-link domain mismatches
- executable, active-content, macro-enabled, archive, double-extension, and deceptive-name attachments
- embedded forms, password fields, hidden HTML, QR-code lures, and HTML-only messages
- patterns learned from locally labeled phishing and legitimate messages

## Install on PowerShell

Python 3.11 or newer is required. There are no runtime dependencies.

```powershell
cd "C:\path\to\phishlens"
py -m pip install -e .
phishlens --version
```

## Desktop GUI

If you prefer clicking instead of typing, launch the desktop app:

```powershell
phishlens gui
```

The GUI lets you:

- load an existing JSON model
- analyze one exported `.eml` file with risk cards and explainable findings
- scan a whole folder and rank messages by risk
- select a finding to read its evidence or open a message's full report
- copy or save reports without using the terminal
- train a new local model without freezing the window

You can also preload a model when opening the app:

```powershell
phishlens gui --model phishlens-model.json
```

## Analyze exported email

Save or drag a suspicious message from the mail application as an `.eml` file, then run:

```powershell
phishlens analyze "C:\Users\Erenn\Desktop\suspicious.eml"
```

The original short form remains supported:

```powershell
phishlens "C:\Users\Erenn\Desktop\suspicious.eml"
phishlens examples\suspicious.eml --json
```

Scan every `.eml` in a folder, optionally including subfolders:

```powershell
phishlens scan "C:\Users\Erenn\Desktop\mail-samples"
phishlens scan "C:\Users\Erenn\Desktop\mail-samples" --recursive --json
```

## Train a local model

Training is supervised: every email needs a correct label. Create this layout and place exported `.eml` files into the matching folder:

```text
training-data/
|-- phishing/
|   |-- known-phish-001.eml
|   `-- known-phish-002.eml
`-- legitimate/
    |-- normal-mail-001.eml
    `-- normal-mail-002.eml
```

Train and use the model:

```powershell
phishlens train training-data --output phishlens-model.json
phishlens analyze "C:\Users\Erenn\Desktop\suspicious.eml" --model phishlens-model.json
phishlens scan "C:\Users\Erenn\Desktop\mail-samples" --recursive --model phishlens-model.json
```

A tiny dataset is included only to test the workflow:

```powershell
phishlens train examples\training-data --output demo-model.json
phishlens analyze examples\suspicious.eml --model demo-model.json
```

Do not use the demo model for real decisions. Start with at least 50 varied messages per label to test the idea; hundreds or thousands of accurately labeled messages are substantially better. Keep the classes reasonably balanced, remove duplicates, and reserve newer messages for a final test that is not used during training. The model stores aggregate token counts and vocabulary, which may still contain sensitive words, so personal datasets and models are ignored by Git by default.

## Scan Gmail or Outlook

Mailbox scans use TLS IMAP, open the folder read-only, and fetch with `BODY.PEEK[]` so messages are not marked as read. Secrets are read from environment variables rather than command-line arguments.

Gmail with an app password:

```powershell
$env:PHISHLENS_IMAP_USERNAME = "you@gmail.com"
$env:PHISHLENS_IMAP_PASSWORD = "your-app-password"
phishlens mailbox --provider gmail --auth password --limit 10 --unread-only --model phishlens-model.json
Remove-Item Env:PHISHLENS_IMAP_PASSWORD
```

Outlook with a short-lived OAuth 2 access token:

```powershell
$env:PHISHLENS_IMAP_USERNAME = "you@outlook.com"
$env:PHISHLENS_OAUTH_TOKEN = "your-access-token"
phishlens mailbox --provider outlook --auth oauth2 --limit 10 --model phishlens-model.json
Remove-Item Env:PHISHLENS_OAUTH_TOKEN
```

OAuth application registration and token refresh are provider-specific and are not automated yet. Never commit passwords, tokens, private emails, training data, or personal model files.

## Scoring

Without a model, the final score is the heuristic score. When a model recognizes at least three features and gives a phishing probability of 65% or more, PhishLens blends 45% of the heuristic score with 55% of the model probability. A model never lowers a heuristic warning, and an uncertain model does not raise the score. Scores below 20 are `low-risk`, 20-49 are `suspicious`, and 50 or higher are `high-risk`.

CLI exit codes are `0` for no high-risk result, `1` when at least one result is high-risk, and `2` for an operational error.

## Tests

```powershell
$env:PYTHONPATH = "src"
py -m unittest discover -s tests -v
```

## License

MIT
