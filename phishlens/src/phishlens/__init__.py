"""FhniX public API."""

from .analyzer import AnalysisResult, analyze_eml
from .classifier import NaiveBayesModel

__all__ = ["AnalysisResult", "NaiveBayesModel", "analyze_eml"]
__version__ = "0.5.0"
