"""Email text classifier loader.

A model is used ONLY if a trained artifact and its evaluation card exist
(produced by scripts/email_dataset/train_email_baseline.py after the dataset
audit). Otherwise the ML layer is reported as UNAVAILABLE — never simulated."""
import json
import os
from typing import Any, Dict

import joblib

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(HERE, "email_text_model.pkl")
CARD_PATH = os.path.join(HERE, "email_model_card.json")

_model = None
_card = None
_load_error = None


def _load():
    global _model, _card, _load_error
    if _model is not None or _load_error is not None:
        return
    if not (os.path.exists(MODEL_PATH) and os.path.exists(CARD_PATH)):
        _load_error = ("No validated email model has been trained yet. The email datasets must be downloaded "
                       "and audited first (see datasets/email_intelligence/reports/DATASET_AUDIT_REPORT.md).")
        return
    try:
        with open(CARD_PATH) as f:
            _card = json.load(f)
        _model = joblib.load(MODEL_PATH)
    except Exception as e:
        _load_error = f"Email model could not be loaded: {type(e).__name__}"
        _model = None


def model_status() -> Dict[str, Any]:
    _load()
    if _model is None:
        return {"available": False, "reason": _load_error}
    return {"available": True, "card": _card}


def predict(subject: str, body_text: str) -> Dict[str, Any]:
    _load()
    if _model is None:
        return {"status": "UNAVAILABLE", "reason": _load_error, "probability": None}
    text = f"{subject or ''}\n{body_text or ''}"
    if len(text.strip()) < 20:
        return {"status": "UNAVAILABLE", "reason": "Too little text for the text model", "probability": None}
    try:
        proba = float(_model.predict_proba([text])[0][1])
    except Exception as e:
        return {"status": "UNAVAILABLE", "reason": f"Prediction failed: {type(e).__name__}", "probability": None}
    return {
        "status": "OK",
        "probability": proba,
        "positive_class": (_card or {}).get("positive_class", "malicious"),
        "model_version": (_card or {}).get("model_version"),
        "trained_on": (_card or {}).get("training_sources"),
        "evaluation": (_card or {}).get("headline_metrics"),
        "note": "Model probability is a statistical estimate from message text only, not certainty and not a verdict.",
    }
