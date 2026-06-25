"""
Sentrix Prediction Engine — Package Init

Exposes PredictionEngine as the primary entry point.
"""
import sys
import os

# Make prediction-engine internal modules importable
_ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
if _ENGINE_DIR not in sys.path:
    sys.path.insert(0, _ENGINE_DIR)

from engine import PredictionEngine

__all__ = ["PredictionEngine"]
__version__ = "1.0.0"
