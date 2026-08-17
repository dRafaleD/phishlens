from __future__ import annotations

import sys
import tempfile
import unittest
from email import policy
from email.parser import BytesParser
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from phishlens.analyzer import analyze_message  # noqa: E402
from phishlens.classifier import (  # noqa: E402
    ModelPrediction,
    NaiveBayesModel,
    extract_features,
    train_from_directory,
)


def parse_message(subject: str, body: str):
    raw = (
        "From: sender@example.com\n"
        f"Subject: {subject}\n"
        "Content-Type: text/plain; charset=utf-8\n\n"
        f"{body}\n"
    )
    return BytesParser(policy=policy.default).parsebytes(raw.encode("utf-8"))


class ClassifierTests(unittest.TestCase):
    def _dataset(self, root: Path) -> None:
        phishing = root / "phishing"
        legitimate = root / "legitimate"
        phishing.mkdir()
        legitimate.mkdir()
        for index in range(4):
            (phishing / f"phish-{index}.eml").write_text(
                "From: Security <alert@unknown.test>\n"
                "Subject: Urgent account password verification\n"
                "Content-Type: text/plain; charset=utf-8\n\n"
                "Verify your account password now using the login link.\n",
                encoding="utf-8",
            )
            (legitimate / f"legit-{index}.eml").write_text(
                "From: Team <team@example.com>\n"
                "Subject: Weekly project meeting notes\n"
                "Content-Type: text/plain; charset=utf-8\n\n"
                "The team meeting schedule and project report are attached to our notes.\n",
                encoding="utf-8",
            )

    def test_trains_saves_and_loads_model(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._dataset(root)

            model, report = train_from_directory(root, validation_split=0.25, seed=7)
            model_path = root / "model.json"
            model.save(model_path)
            loaded = NaiveBayesModel.load(model_path)
            prediction = loaded.predict_message(
                parse_message("Account verification", "Verify the password and login to your account now.")
            )

            self.assertGreater(prediction.phishing_probability, 0.9)
            self.assertEqual(prediction.label, "phishing")
            self.assertIsNotNone(report.validation)
            self.assertGreater(report.vocabulary_size, 10)

    def test_model_can_raise_the_combined_score(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._dataset(root)
            model, _ = train_from_directory(root, validation_split=0)
            message = parse_message(
                "Account verification",
                "Verify the password and login to your account using the secure portal.",
            )

            result = analyze_message(message, model=model)

            self.assertIsNotNone(result.model_prediction)
            self.assertGreater(result.score, result.heuristic_score)
            self.assertEqual(result.model_prediction.label, "phishing")

    def test_uncertain_model_does_not_raise_score(self) -> None:
        class UncertainModel:
            def predict_message(self, message):
                return ModelPrediction(phishing_probability=0.5, label="uncertain", known_tokens=10)

        result = analyze_message(
            parse_message("Project update", "The project meeting is tomorrow."),
            model=UncertainModel(),
        )

        self.assertEqual(result.score, result.heuristic_score)
        self.assertEqual(result.verdict, "low-risk")

    def test_extracts_structural_phishing_features(self) -> None:
        message = BytesParser(policy=policy.default).parsebytes(
            b"From: Security <sender@example.com>\n"
            b"Reply-To: collect@attacker.test\n"
            b"Authentication-Results: mx.example; spf=fail; dkim=fail\n"
            b"Content-Type: text/html; charset=utf-8\n\n"
            b"<form><input type='password'>"
            b"<a href='http://xn--micrsoft-2za.test/login'>Verify</a></form>\n"
        )

        features = extract_features(message)

        self.assertIn("structure:form", features)
        self.assertIn("structure:password-input", features)
        self.assertIn("structure:sender-reply-mismatch", features)
        self.assertIn("auth-failure:spf", features)
        self.assertIn("url:punycode", features)


if __name__ == "__main__":
    unittest.main()
