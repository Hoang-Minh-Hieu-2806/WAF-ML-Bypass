"""T03 — ML-WAF stub scoring API (lab local only).

Phase 1 (Hieu): tra ve nhan gia de compose healthy + team test integration.
Tuan 05-06 (Hoang ML): thay rule-based bang TF-IDF + LogisticRegression/SVM,
load model .joblib (bi .gitignore chan), giu nguyen contract JSON.
Contract (xem docs/interfaces.md):
  POST /score {"text": "..."} -> {"label": "benign|malicious", "score": 0..1,
                                   "model_version": str}
"""
import os
import re

from fastapi import FastAPI
from pydantic import BaseModel

MODEL_VERSION = os.getenv("MODEL_VERSION", "stub-0.1")
PORT = int(os.getenv("PORT", "5001"))

SUSPICIOUS = re.compile(
    r"(\bunion\b|\bselect\b|\bor\b\s+\d+\s*=\s*\d+|--|#|/\*|%27|%22|%3b|<script)",
    re.IGNORECASE,
)

app = FastAPI(title="waf-ml stub", version=MODEL_VERSION)


class ScoreIn(BaseModel):
    text: str = ""


@app.get("/health")
def health():
    return {"status": "ok", "model_version": MODEL_VERSION}


@app.post("/score")
def score(item: ScoreIn):
    t = item.text or ""
    malicious = bool(SUSPICIOUS.search(t))
    return {
        "label": "malicious" if malicious else "benign",
        "score": 0.9 if malicious else 0.1,
        "model_version": MODEL_VERSION,
    }
