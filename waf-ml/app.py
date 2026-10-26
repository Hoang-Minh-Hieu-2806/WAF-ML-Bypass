"""T03 — ML-WAF scoring API + enforcement reverse proxy (lab local only).

Contract (docs/interfaces.md §3):
  POST /score {"text": "..."} -> {"label": "benign|malicious", "score": 0..1,
                                   "model_version": str}
  GET  /health -> {"status":"ok","model_version":"..."}

Mọi route khác (/search, /product, /login, ...) đi qua ML enforcement:
  score < ML_THRESHOLD  -> forward nguyên request tới ML_BACKEND
  score >= ML_THRESHOLD -> HTTP 403, không chạm backend

Proxy giữ nguyên raw query/body và duplicate parameters khi forward. Text đưa
vào model chỉ là projection phục vụ scoring; wire request không bị dựng lại.

Phase 1 (Hiếu): regex stub để compose healthy + test integration.
Tuần 05-06 (Hoàng ML + Hiếu): pipeline TF-IDF + LogisticRegression được
train.py train trong container (server.py), app.py load model.joblib từ
$ML_MODEL_DIR; nếu thiếu model quay lại regex stub nhưng contract không đổi.
"""
import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from http.client import HTTPConnection
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

MODEL_DIR = Path(os.getenv("ML_MODEL_DIR", "artifacts"))
MODEL_VERSION = "stub-0.1"
ML_THRESHOLD = float(os.getenv("ML_THRESHOLD", "0.5"))
if not 0.0 <= ML_THRESHOLD <= 1.0:
    raise RuntimeError("ML_THRESHOLD must be between 0 and 1")
ML_BACKEND = os.getenv("ML_BACKEND", "http://web-app:5000")
ML_EVIDENCE_LOG = Path(os.getenv("ML_EVIDENCE_LOG", "/evidence/ml.jsonl"))
_pipeline = None
_malicious_index = None
_evidence_lock = threading.Lock()

HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "content-length", "host",
}

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
        probability = 0.9 if SUSPICIOUS.search(text) else 0.1
        return ("malicious" if probability >= ML_THRESHOLD else "benign"), probability
    prob = float(_pipeline.predict_proba([text or ""])[0][_malicious_index])
    label = "malicious" if prob >= ML_THRESHOLD else "benign"
    return label, round(prob, 4)


def _score_text(raw_query: bytes, body: bytes, content_type: str) -> str:
    """Extract values for the classifier without changing the forwarded wire data."""
    values = [value for _, value in parse_qsl(
        raw_query.decode("utf-8", errors="replace"), keep_blank_values=True)]
    if body:
        decoded = body.decode("utf-8", errors="replace")
        if content_type.split(";", 1)[0].strip().lower() == "application/x-www-form-urlencoded":
            values.extend(value for _, value in parse_qsl(decoded, keep_blank_values=True))
        else:
            values.append(decoded)
    return " ".join(values)


def _write_evidence(record):
    ML_EVIDENCE_LOG.parent.mkdir(parents=True, exist_ok=True)
    with _evidence_lock, ML_EVIDENCE_LOG.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, ensure_ascii=False) + "\n")


def _forward(method, raw_path, body, incoming_headers):
    backend = urlsplit(ML_BACKEND)
    if backend.scheme != "http" or not backend.hostname:
        raise RuntimeError("ML_BACKEND must be an http:// URL")
    base_path = backend.path.rstrip("/")
    target = base_path + raw_path
    headers = {
        key: value for key, value in incoming_headers.items()
        if key.lower() not in HOP_BY_HOP_HEADERS
    }
    headers["Host"] = backend.netloc
    connection = HTTPConnection(backend.hostname, backend.port or 80, timeout=15)
    try:
        connection.request(method, target, body=body or None, headers=headers)
        response = connection.getresponse()
        response_body = response.read()
        response_headers = {
            key: value for key, value in response.getheaders()
            if key.lower() not in HOP_BY_HOP_HEADERS
        }
        return response.status, response_body, response_headers
    finally:
        connection.close()


@app.get("/health")
def health():
    return {"status": "ok", "model_version": MODEL_VERSION}


@app.post("/score")
def score(item: ScoreIn):
    label, prob = _predict(item.text or "")
    return {"label": label, "score": prob, "model_version": MODEL_VERSION}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def enforce(path: str, request: Request):
    """Classify then block/forward while recording one correlated decision."""
    body = await request.body()
    raw_query = request.scope.get("query_string", b"")
    raw_path = "/" + path + (("?" + raw_query.decode("ascii", errors="replace"))
                             if raw_query else "")
    text = _score_text(raw_query, body, request.headers.get("content-type", ""))
    label, probability = _predict(text)
    blocked = label == "malicious"
    case_id = request.headers.get("x-lab-case-id")
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "case_id": case_id,
        "method": request.method,
        "raw_target": raw_path,
        "raw_body": body.decode("utf-8", errors="replace"),
        "content_type": request.headers.get("content-type"),
        "transfer_encoding": request.headers.get("transfer-encoding"),
        "score_text": text,
        "label": label,
        "score": probability,
        "threshold": ML_THRESHOLD,
        "model_version": MODEL_VERSION,
        "decision": "blocked" if blocked else "allowed",
        "backend_status": None,
        "error": None,
    }
    response_headers = {
        "X-ML-Decision": record["decision"],
        "X-ML-Score": str(probability),
        "X-ML-Model-Version": MODEL_VERSION,
    }
    if case_id:
        response_headers["X-Lab-Case-ID"] = case_id
    if blocked:
        _write_evidence(record)
        return JSONResponse(
            status_code=403,
            content={"detail": "blocked by ML-WAF", "label": label,
                     "score": probability, "threshold": ML_THRESHOLD,
                     "model_version": MODEL_VERSION},
            headers=response_headers,
        )
    try:
        status, response_body, backend_headers = _forward(
            request.method, raw_path, body, dict(request.headers))
        record["backend_status"] = status
        _write_evidence(record)
        backend_headers.update(response_headers)
        return Response(content=response_body, status_code=status, headers=backend_headers)
    except Exception as exc:  # backend outage is evidence, never silently allow
        record["decision"] = "error"
        record["error"] = f"{type(exc).__name__}: {exc}"
        _write_evidence(record)
        return JSONResponse(status_code=502,
                            content={"detail": "ML-WAF backend unavailable"},
                            headers=response_headers)
