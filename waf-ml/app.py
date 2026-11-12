"""ML-WAF scoring API with v1.0 compatibility and 3-class P1 enforcement."""
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

MODEL_DIR = Path(os.getenv("ML_MODEL_DIR", "artifacts/v1.1"))
MODEL_VERSION = "stub-3cls"
ML_THRESHOLD = float(os.getenv("ML_THRESHOLD", "0.5"))
if not 0.0 <= ML_THRESHOLD <= 1.0:
    raise RuntimeError("ML_THRESHOLD must be between 0 and 1")
ML_BACKEND = os.getenv("ML_BACKEND", "http://web-app:5000")
ML_EVIDENCE_LOG = Path(os.getenv("ML_EVIDENCE_LOG", "/evidence/ml.jsonl"))
_pipeline = None
_class_indices = {}
_legacy_binary = False
_evidence_lock = threading.Lock()
HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "content-length", "host",
}

try:
    if (MODEL_DIR / "model.joblib").exists():
        import joblib
        _pipeline = joblib.load(MODEL_DIR / "model.joblib")
        _class_indices = {str(label): i for i, label in enumerate(_pipeline.classes_)}
        meta = json.loads((MODEL_DIR / "metrics.json").read_text(encoding="utf-8"))
        MODEL_VERSION = meta.get("model_version", "unknown")
        _legacy_binary = set(_class_indices) == {"benign", "malicious"}
        if not _legacy_binary and set(_class_indices) != {"benign", "sqli", "xss"}:
            raise ValueError(f"Unsupported model classes: {sorted(_class_indices)}")
    else:
        MODEL_VERSION = "stub-3cls"
except Exception:
    logging.getLogger("waf_ml.model").warning(
        "ML model load FAILED at %s; degraded 3-class regex stub is active",
        str(MODEL_DIR), exc_info=True)
    _pipeline = None
    _class_indices = {}
    _legacy_binary = False
    MODEL_VERSION = "stub-3cls"
MODEL_VERSION = os.getenv("ML_MODEL_VERSION", MODEL_VERSION)

SUSPICIOUS_SQLI = re.compile(
    r"(\bunion\b|\bselect\b|\bor\b\s+\d+\s*=\s*\d+|--|#|/\*|%27|%22|%3b)",
    re.IGNORECASE,
)
SUSPICIOUS_XSS = re.compile(r"(<\s*script|onerror\s*=|onload\s*=|javascript:)", re.IGNORECASE)
app = FastAPI(title="waf-ml", version=MODEL_VERSION)


def _predict(text: str):
    text = text or ""
    if _pipeline is not None:
        probabilities = _pipeline.predict_proba([text])[0]
        if _legacy_binary:
            probability = float(probabilities[_class_indices["malicious"]])
            label = "malicious" if probability >= ML_THRESHOLD else "benign"
            return label, round(probability, 4)
        scores = {name: float(probabilities[_class_indices[name]])
                  for name in ("benign", "sqli", "xss")}
        return max(scores, key=scores.get), scores
    if _legacy_binary:
        probability = 0.9 if SUSPICIOUS_SQLI.search(text) or SUSPICIOUS_XSS.search(text) else 0.1
        return ("malicious" if probability >= ML_THRESHOLD else "benign"), probability
    if SUSPICIOUS_XSS.search(text):
        scores = {"benign": 0.05, "sqli": 0.05, "xss": 0.90}
    elif SUSPICIOUS_SQLI.search(text):
        scores = {"benign": 0.05, "sqli": 0.90, "xss": 0.05}
    else:
        scores = {"benign": 0.90, "sqli": 0.05, "xss": 0.05}
    return max(scores, key=scores.get), scores


def _attack_score(score):
    if isinstance(score, dict):
        return float(score.get("sqli", 0.0)) + float(score.get("xss", 0.0))
    return float(score)


def _decision(label, score):
    return _attack_score(score) >= ML_THRESHOLD if isinstance(score, dict) else score >= ML_THRESHOLD


def _score_text(raw_query: bytes, body: bytes, content_type: str) -> str:
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
    target = backend.path.rstrip("/") + raw_path
    headers = {key: value for key, value in incoming_headers.items()
               if key.lower() not in HOP_BY_HOP_HEADERS}
    headers["Host"] = backend.netloc
    connection = HTTPConnection(backend.hostname, backend.port or 80, timeout=15)
    try:
        connection.request(method, target, body=body or None, headers=headers)
        response = connection.getresponse()
        response_body = response.read()
        response_headers = {key: value for key, value in response.getheaders()
                            if key.lower() not in HOP_BY_HOP_HEADERS}
        return response.status, response_body, response_headers
    finally:
        connection.close()


@app.get("/health")
def health():
    return {"status": "ok", "model_version": MODEL_VERSION}


@app.post("/score")
def score(item: dict):
    label, scores = _predict(item.get("text") or "")
    if isinstance(scores, dict):
        return {"label": label, "score": scores, "model_version": MODEL_VERSION,
                "degraded": _pipeline is None}
    return {"label": label, "score": scores, "model_version": MODEL_VERSION}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def enforce(path: str, request: Request):
    body = await request.body()
    raw_query = request.scope.get("query_string", b"")
    raw_path = "/" + path + (("?" + raw_query.decode("ascii", errors="replace")) if raw_query else "")
    text = _score_text(raw_query, body, request.headers.get("content-type", ""))
    label, score_value = _predict(text)
    attack_score = _attack_score(score_value)
    blocked = _decision(label, score_value)
    attack_class = (max(("sqli", "xss"), key=lambda key: score_value.get(key, 0.0))
                    if blocked and isinstance(score_value, dict) else None)
    case_id = request.headers.get("x-lab-case-id")
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(), "case_id": case_id,
        "method": request.method, "raw_target": raw_path,
        "raw_body": body.decode("utf-8", errors="replace"),
        "content_type": request.headers.get("content-type"),
        "transfer_encoding": request.headers.get("transfer-encoding"),
        "score_text": text, "label": label, "threshold": ML_THRESHOLD,
        "model_version": MODEL_VERSION, "decision": "blocked" if blocked else "allowed",
        "backend_status": None, "error": None, "degraded": _pipeline is None,
    }
    if isinstance(score_value, dict):
        record.update(scores=score_value, attack_score=attack_score)
        if attack_class:
            record["attack_class"] = attack_class
    else:
        record["score"] = score_value
    response_headers = {
        "X-ML-Decision": record["decision"], "X-ML-Score": str(attack_score),
        "X-ML-Model-Version": MODEL_VERSION,
    }
    if isinstance(score_value, dict):
        response_headers["X-ML-Attack-Score"] = str(attack_score)
    if case_id:
        response_headers["X-Lab-Case-ID"] = case_id
    if blocked:
        _write_evidence(record)
        content = {"detail": "blocked by ML-WAF", "label": label,
                   "score": score_value, "threshold": ML_THRESHOLD,
                   "model_version": MODEL_VERSION, "degraded": _pipeline is None}
        if isinstance(score_value, dict):
            content.update(attack_score=attack_score, attack_class=attack_class)
        return JSONResponse(status_code=403, content=content, headers=response_headers)
    try:
        status, response_body, backend_headers = _forward(
            request.method, raw_path, body, dict(request.headers))
        record["backend_status"] = status
        _write_evidence(record)
        backend_headers.update(response_headers)
        return Response(content=response_body, status_code=status, headers=backend_headers)
    except Exception as exc:
        record["decision"] = "error"
        record["error"] = f"{type(exc).__name__}: {exc}"
        _write_evidence(record)
        return JSONResponse(status_code=502,
                            content={"detail": "ML-WAF backend unavailable"},
                            headers=response_headers)
