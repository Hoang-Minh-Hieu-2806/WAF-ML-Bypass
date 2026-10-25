"""T03 — ML-WAF scoring API (lab local only).

Contract (docs/interfaces.md §3):
  POST /score {"text": "..."} -> {"label": "benign|malicious", "score": 0..1,
                                   "model_version": str}
  GET  /health -> {"status":"ok","model_version":"..."}

Phase 1 (Hiếu): regex stub để compose healthy + test integration.
Tuần 05-06 (Hoàng ML + Hiếu): pipeline TF-IDF + LogisticRegression được
train.py train trong container (server.py), app.py load model.joblib từ
$ML_MODEL_DIR; nếu thiếu model quay lại regex stub nhưng contract không đổi.
"""
import json
import logging
import os
import re
from pathlib import Path

from fastapi import FastAPI
from pydantic import BaseModel

MODEL_DIR = Path(os.getenv("ML_MODEL_DIR", "artifacts"))
MODEL_VERSION = "stub-0.1"
_pipeline = None
_malicious_index = None

try:
    if (MODEL_DIR / "model.joblib").exists():
        import joblib

        _pipeline = joblib.load(MODEL_DIR / "model.joblib")
        _malicious_index = list(_pipeline.classes_).index("malicious")
        meta = json.loads((MODEL_DIR / "metrics.json").read_text(encoding="utf-8"))
        MODEL_VERSION = meta.get("model_version", "lr-tfidf-1.0")
except Exception:  # noqa: BLE001 — fallback rõ ràng, không silent
    logging.getLogger("waf_ml.model").warning(
        "ML model load FAILED at %s — falling back to regex stub "
        "(model_version=stub-0.1, score quality degraded)",
        str(MODEL_DIR),
        exc_info=True,
    )
    _pipeline = None
    MODEL_VERSION = "stub-0.1"

# server.py train xong sẽ set env này trước khi import app; ưu tiên env.
MODEL_VERSION = os.getenv("ML_MODEL_VERSION", MODEL_VERSION)

SUSPICIOUS = re.compile(
    r"(\bunion\b|\bselect\b|\bor\b\s+\d+\s*=\s*\d+|--|#|/\*|%27|%22|%3b|<script)",
    re.IGNORECASE,
)

app = FastAPI(title="waf-ml", version=MODEL_VERSION)


class ScoreIn(BaseModel):
    text: str = ""


def _predict(text: str):
    if _pipeline is None:
        malicious = bool(SUSPICIOUS.search(text))
        return ("malicious" if malicious else "benign"), (0.9 if malicious else 0.1)
    prob = float(_pipeline.predict_proba([text or ""])[0][_malicious_index])
    label = "malicious" if prob >= 0.5 else "benign"
    return label, round(prob, 4)


@app.get("/health")
def health():
    return {"status": "ok", "model_version": MODEL_VERSION}


@app.post("/score")
def score(item: ScoreIn):
    label, prob = _predict(item.text or "")
    return {"label": label, "score": prob, "model_version": MODEL_VERSION}
