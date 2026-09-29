"""
Detector Module for Decoupling Machine Learning Ingestion.
"""

from .adapter import DetectorAdapter, MockDetector, SklearnModelDetector, get_detector

__all__ = [
    "DetectorAdapter",
    "MockDetector",
    "SklearnModelDetector",
    "get_detector",
]
