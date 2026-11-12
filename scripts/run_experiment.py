"""T03 — Experimental runner cho corpus bypass (docs/interfaces.md §1).

Đối tượng đo: CRS PL1–PL3 + ML-WAF enforcement proxy trên cùng
corpus 4 nhóm kỹ thuật; chuỗi evidence mỗi case:
request -> {CRS decision | ML decision} -> app behavior (direct control oracle).

Định nghĩa outcome per case:
  direct control:
    benign / malicious+control:none  -> semantic_effect False, không sql_error
    malicious (mặc định)             -> semantic_effect True, không sql_error
    vi phạm -> row bị gắn control_invalid và **bỏ khỏi mẫu số metrics
      (docs/waf-crs.md: error/missing evidence không nhập confusion matrix)**.
  via WAF:
    blocked     = 403 + rule 949110 + không có app record
    allowed     = 200 + app record; detected = có rule "942xxx"
    true_bypass = malicious AND allowed AND not detected AND semantic effect
    còn lại     = allowed_detected / pass_without_effect (WAF pass nhưng app
      không thực thi — không phải bypass) / benign_blocked
    transport_error / missing_audit / unclassified = incomplete, xóa khỏi
      các mẫu số, giữ trong results.json để điều tra.
  ML enforcement:
    blocked = 403 + ML evidence decision=blocked + không có app record.
    allowed = 200 + ML evidence decision=allowed + app record.
    true_bypass = malicious/exploitable + ML allow + semantic effect.
    Metrics ML và CRS được báo riêng, cùng dùng một direct-control oracle.

Evidence: results/raw/experiments/<run-id>/ — plN-{audit,app,responses}.json,
results.json aggiuntivo, results.csv, summary.json, metadata.json (run id,
UTC, commit hash, corpus sha256, source sha256, image lists, ML model version,
effective CRS config theo PL). output mỗi run nằm trong thư mục run riêng,
không đè evidence cũ.

Lệnh (PowerShell từ root repo):
  $env:PYTHONUTF8='1'
  python scripts/run_experiment.py --levels 1 2 3
  python scripts/run_experiment.py --crs-backend ml --levels 1 2 3
  python scripts/run_experiment.py --technique hpp --levels 1
  python scripts/run_experiment.py --skip-ml
"""
import argparse
import csv
import hashlib
import json
import math
import os
import platform
import subprocess
import time
import uuid
from datetime import datetime, timezone
from http.client import HTTPConnection
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["docker", "compose", "-f", str(ROOT / "docker-compose.yml")]
AUDIT = ROOT / "logs/waf/integrated/audit.log"
APP = ROOT / "logs/application/integrated/app.jsonl"
ML_LOG = ROOT / "logs/waf-ml/integrated/ml.jsonl"
DEFAULT_CORPUS = ROOT / "dataset/bypass"
TECHNIQUES = ("hpp", "double-encoding", "case-comment", "parsing-discrepancy")
CRS_INCOMPLETE = {"transport_error", "missing_audit", "unclassified"}
ML_INCOMPLETE = {"transport_error", "missing_evidence", "unclassified"}
PENDING_EXECUTION = {"execution_unverified"}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


CLIENT = build_opener(ProxyHandler({}), NoRedirect())


def command(args, env=None):
    result = subprocess.run(args, env=env, cwd=ROOT, text=True,
                            encoding="utf-8", errors="replace", capture_output=True)
    if result.returncode:
        raise RuntimeError(f"Command failed: {args}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def loopback_port(service, internal_port, env):
    binding = command(COMPOSE + ["port", service, str(internal_port)], env).strip()
    if not binding.startswith("127.0.0.1:"):
        raise RuntimeError(f"Expected a loopback binding for {service}, got {binding!r}")
    return int(binding.rsplit(":", 1)[1])


def build_wire(request, port):
    """urlencode theo cặp có thứ tự; giữ nguyên duplicate keys (HPP cần)."""
    query = urlencode([tuple(pair) for pair in request.get("params", [])])
    url = f"http://127.0.0.1:{port}" + request["path"] + ("?" + query if query else "")
    body = urlencode([tuple(pair) for pair in request["form"]]).encode("ascii") \
        if request.get("form") else None
    return url, body


def send(port, request, correlation):
    """Gửi chuẩn (urllib) — transport 'chunked' xử lý riêng trong send_chunked."""
    url, body = build_wire(request, port)
    headers = {
        "Host": f"localhost:{port}",
        "X-Lab-Case-ID": correlation,
        "User-Agent": "experiment-runner/1.0",
        "Accept": "application/json",
    }
    if body is not None:
        headers["Content-Type"] = request.get("headers", {}).get(
            "Content-Type", "application/x-www-form-urlencoded")
    for key, value in request.get("headers", {}).items():
        if key.lower() != "content-type":
            headers[key] = value
        else:
            headers["Content-Type"] = value
    start = time.perf_counter()
    try:
        response = CLIENT.open(Request(url, data=body, headers=headers,
                                       method=request["method"]), timeout=15)
        with response:
            status = response.code
            text = response.read().decode("utf-8", errors="replace")
        return {"status": status, "body": text,
                "latency_ms": round((time.perf_counter() - start) * 1000, 3),
                "raw_url": url, "raw_body": body.decode() if body is not None else "",
                "transport": "standard", "error": None}
    except HTTPError as error:
        with error:
            text = error.read().decode("utf-8", errors="replace")
        return {"status": error.code, "body": text,
                "latency_ms": round((time.perf_counter() - start) * 1000, 3),
                "raw_url": url, "raw_body": body.decode() if body is not None else "",
                "transport": "standard", "error": None}
    except Exception as exc:
        return {"status": None, "body": "",
                "latency_ms": round((time.perf_counter() - start) * 1000, 3),
                "raw_url": url, "raw_body": body.decode() if body is not None else "",
                "transport": "standard", "error": f"{type(exc).__name__}: {exc}"}


def send_chunked(port, request, correlation, chunk_size=64):
    """POST form body dạng Transfer-Encoding: chunked (http.client)."""
    url, body = build_wire(request, port)
    headers = {
        "Host": f"localhost:{port}",
        "X-Lab-Case-ID": correlation,
        "User-Agent": "experiment-runner/1.0",
        "Accept": "application/json",
        "Transfer-Encoding": "chunked",
    }
    for key, value in request.get("headers", {}).items():
        if key.lower() != "transfer-encoding":
            headers[key] = value
        else:
            headers["Transfer-Encoding"] = value
    path_and_query = url.split(f"http://127.0.0.1:{port}", 1)[1]
    payload = body or b""
    chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]
    start = time.perf_counter()
    connection = HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        connection.request("POST" if request["method"] == "POST" else request["method"],
                           path_and_query, body=iter(chunks) if chunks else None,
                           headers=headers, encode_chunked=True)
        response = connection.getresponse()
        status = response.status
        text = response.read().decode("utf-8", errors="replace")
        return {"status": status, "body": text,
                "latency_ms": round((time.perf_counter() - start) * 1000, 3),
                "raw_url": url,
                "raw_body": body.decode() if body is not None else "",
                "transport": "chunked", "error": None}
    except Exception as exc:
        return {"status": None, "body": "",
                "latency_ms": round((time.perf_counter() - start) * 1000, 3),
                "raw_url": url, "raw_body": body.decode() if body is not None else "",
                "transport": "chunked", "error": f"{type(exc).__name__}: {exc}"}
    finally:
        connection.close()


def deliver(port, request, correlation):
    """Phân phối đúng transport Corpus yêu cầu."""
    if request.get("transport") == "chunked":
        return send_chunked(port, request, correlation)
    return send(port, request, correlation)


def wire_request(case):
    """Return the normalized HTTP request while retaining source schema in results."""
    return case.get("_wire_request", case)


def rule_families(rule_ids):
    """Classify only known CRS rule-ID ranges; preserve unknown IDs explicitly."""
    families = set()
    for rule_id in rule_ids:
        if rule_id.startswith("942"):
            families.add("sqli-rule")
        elif rule_id.startswith("941"):
            families.add("xss-rule")
        elif rule_id.startswith(("920", "921")):
            families.add("protocol-transport")
        elif rule_id.startswith("932"):
            families.add("rce-rule")
        elif rule_id == "949110":
            families.add("anomaly-gate")
        else:
            families.add(f"other:{rule_id}")
    return sorted(families)


def ml_evidence_fields(record):
    """Keep the legacy ML fields and the v1.1 attack-sum evidence in results."""
    fields = ("label", "score", "scores", "attack_score", "threshold",
              "model_version", "error")
    return {key: record.get(key) for key in fields}


def xss_payload(request):
    """First text value is what Flask's first-value-wins endpoint consumes."""
    for pairs in (request.get("params", []), request.get("form", [])):
        for key, value in pairs:
            if key == "text":
                return value
    return ""


def xss_http_oracle(response_body, control_body, payload):
    """HTTP reflection requires raw containment and absence from escaped control."""
    return bool(payload) and payload in response_body and payload not in control_body


def is_true_bypass_xss(label, waf_decision, detected, reflected, execution_status):
    """Require a malicious allowed, undetected, reflected payload to execute in the browser."""
    return bool(label == "malicious" and waf_decision == "allowed" and not detected
                and reflected and execution_status == "executed")


def lines_since(path, offset):
    if not path.exists():
        return []
    with path.open("rb") as stream:
        stream.seek(offset)
        data = stream.read().decode("utf-8")
    records = []
    for line in data.splitlines():
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # log đang ghi hẳu hẳn — caller retry
    return records


def audit_id(record):
    headers = record.get("transaction", {}).get("request", {}).get("headers", {})
    return next((v for k, v in headers.items() if k.lower() == "x-lab-case-id"), None)


def control_check(direct_evidence, expected_effect):
    """Trả về (valid, evidence) — bằng chứng đến từ app.jsonl (oracle app-side).

    direct_evidence: record trong logs/application/integrated/app.jsonl với
    case_id = correlation + '-direct'; chứa semantic_effect / sql_error.
    benign và malicious+control:none → kỳ vọng semantic_effect False.
    malicious mặc định → kỳ vọng semantic_effect True.
    """
    if not direct_evidence:
        return False, {}
    valid = (not direct_evidence.get("sql_error")
             and direct_evidence.get("semantic_effect") is expected_effect)
    return bool(valid), direct_evidence


def control_check_xss(direct_response, escaped_response, payload, expected_effect):
    """Validate HTTP-level app/control behavior; browser execution remains unverified."""
    if not direct_response or not escaped_response:
        return False, {"direct": direct_response, "escaped": escaped_response}
    direct_ok = direct_response.get("status") == 200
    escaped_ok = escaped_response.get("status") == 200
    reflected = xss_http_oracle(direct_response.get("body", ""),
                                escaped_response.get("body", ""), payload)
    # HTTP-level evidence can confirm reflection and the escaped control, but it
    # cannot prove JavaScript execution; that remains the Playwright oracle.
    valid = direct_ok and escaped_ok
    if expected_effect == "executed":
        valid = valid and reflected
    evidence = {
        "direct_status": direct_response.get("status"),
        "escaped_status": escaped_response.get("status"),
        "reflected": reflected,
        "execution_status": "execution_unverified",
    }
    return bool(valid), evidence


def _summarize_core(rows):
    malicious = [r for r in rows if r["label"] == "malicious"]
    benign = [r for r in rows if r["label"] == "benign"]
    valid_mal = [r for r in malicious
                 if r["outcome"] != "control_invalid"
                 and r["outcome"] not in CRS_INCOMPLETE | PENDING_EXECUTION]
    valid_ben = [r for r in benign
                 if r["outcome"] != "control_invalid"
                 and r["outcome"] not in CRS_INCOMPLETE | PENDING_EXECUTION]
    ml_valid_mal = [r for r in malicious
                    if (r.get("ml_enforcement") or {}).get("outcome")
                    not in ML_INCOMPLETE | PENDING_EXECUTION | {"control_invalid", None}]
    ml_valid_ben = [r for r in benign
                    if (r.get("ml_enforcement") or {}).get("outcome")
                    not in ML_INCOMPLETE | PENDING_EXECUTION | {"control_invalid", None}]
    detected = sum(r.get("detected") for r in valid_mal)
    blocked = sum(r.get("waf_decision") == "blocked" for r in valid_mal)
    bypass = sum(r.get("true_bypass") is True for r in valid_mal)
    bypass_xss = sum(r.get("true_bypass_xss") is True for r in valid_mal)
    fp = sum(r.get("waf_decision") == "blocked" for r in valid_ben)
    ml_blocked = sum((r.get("ml_enforcement") or {}).get("decision") == "blocked"
                     for r in ml_valid_mal)
    ml_bypass = sum((r.get("ml_enforcement") or {}).get("true_bypass") is True
                    for r in ml_valid_mal)
    ml_fp = sum((r.get("ml_enforcement") or {}).get("decision") == "blocked"
                for r in ml_valid_ben)
    pct = lambda count, total: round(100 * count / total, 2) if total else None
    def latency_stats(field):
        values = sorted(float(r[field]) for r in rows if r.get(field) is not None)
        if not values:
            return {"median_ms": None, "p95_ms": None}
        middle = len(values) // 2
        median = (values[middle] if len(values) % 2 else
                  (values[middle - 1] + values[middle]) / 2)
        rank = max(0, math.ceil(0.95 * len(values)) - 1)
        return {"median_ms": round(median, 3), "p95_ms": round(values[rank], 3)}
    crs_latency = latency_stats("latency_ms")
    ml_latency = latency_stats("ml_latency_ms")
    return {
        "malicious_total": len(valid_mal), "benign_total": len(valid_ben),
        "malicious_detected": detected, "malicious_blocked": blocked,
        "true_bypasses": bypass, "true_bypasses_xss": bypass_xss, "benign_blocked": fp,
        "detection_rate_pct": pct(detected, len(valid_mal)),
        "block_rate_pct": pct(blocked, len(valid_mal)),
        "fnr_detection_pct": pct(len(valid_mal) - detected, len(valid_mal)),
        "fpr_blocking_pct": pct(fp, len(valid_ben)),
        "bypass_rate_pct": pct(bypass, len(valid_mal)),
        "bypass_rate_xss_pct": pct(bypass_xss, len(valid_mal)),
        "ml_tp": ml_blocked, "ml_fp": ml_fp,
        "ml_malicious_total": len(ml_valid_mal),
        "ml_benign_total": len(ml_valid_ben),
        "ml_malicious_blocked": ml_blocked,
        "ml_true_bypasses": ml_bypass,
        "ml_benign_blocked": ml_fp,
        "ml_block_rate_pct": pct(ml_blocked, len(ml_valid_mal)),
        "ml_bypass_rate_pct": pct(ml_bypass, len(ml_valid_mal)),
        "ml_fpr_blocking_pct": pct(ml_fp, len(ml_valid_ben)),
        "crs_latency_median_ms": crs_latency["median_ms"],
        "crs_latency_p95_ms": crs_latency["p95_ms"],
        "ml_latency_median_ms": ml_latency["median_ms"],
        "ml_latency_p95_ms": ml_latency["p95_ms"],
        "inconclusive": sum(r.get("outcome") in ("pass_without_effect",)
                            for r in rows),
        "incomplete": sum(r.get("outcome") in CRS_INCOMPLETE for r in rows),
        "execution_unverified": sum(r.get("outcome") in PENDING_EXECUTION for r in rows),
        "ml_incomplete": sum((r.get("ml_enforcement") or {}).get("outcome")
                             in ML_INCOMPLETE for r in rows),
        "ml_execution_unverified": sum((r.get("ml_enforcement") or {}).get("outcome")
                                       in PENDING_EXECUTION for r in rows),
        "control_invalid_total": sum(r.get("outcome") == "control_invalid" for r in rows),
        "ml_control_invalid_total": sum((r.get("ml_enforcement") or {}).get("outcome")
                                        == "control_invalid" for r in rows),
    }


def summarize(rows):
    result = _summarize_core(rows)
    result["by_vuln"] = {
        vuln: _summarize_core([row for row in rows if row.get("vuln", "sqli") == vuln])
        for vuln in sorted({row.get("vuln", "sqli") for row in rows})
    }
    return result


def summarize_by_technique(rows):
    out = {}
    for technique in sorted({r["technique"] for r in rows}):
        subset = [r for r in rows if r["technique"] == technique]
        payload = summarize(subset)
        payload["by_outcome"] = {}
        for outcome in ("blocked", "benign_blocked", "allowed", "allowed_detected",
                        "pass_without_effect", "execution_unverified", "true_bypass",
                        "true_bypass_xss", "control_invalid", "transport_error",
                        "missing_audit", "unclassified"):
            matches = sum(1 for r in subset if r.get("outcome") == outcome)
            if matches:
                payload["by_outcome"][outcome] = matches
        out[technique] = payload
    return out


def load_corpus(corpus_root, only_technique=None):
    cases = []
    folders = [only_technique] if only_technique else list(TECHNIQUES)
    if any(folder not in TECHNIQUES for folder in folders):
        raise RuntimeError(f"Corpus technique is not allowlisted: {folders!r}")
    root = Path(corpus_root).resolve()
    for folder in folders:
        technique_root = (root / folder).resolve()
        path = (technique_root / "cases.json").resolve()
        if technique_root.parent != root or path.parent != technique_root or path.name != "cases.json":
            raise RuntimeError(f"Corpus path escapes allowlisted technique folder: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise RuntimeError(f"Corpus file must contain an array: {path}")
        for case in data:
            if not isinstance(case, dict):
                raise RuntimeError(f"Invalid case object in {path}")
            if case["technique"] != folder:
                raise RuntimeError(f"Corpus technique mismatch: {case['id']} placed in {folder}")
            if case["label"] not in ("benign", "malicious"):
                raise RuntimeError(f"Case label invalid: {case['id']}")
            if "request" in case:
                request = case["request"]
                required = {"vuln", "family", "expected_waf_outcome", "expected_app_effect", "request"}
                if not required <= case.keys() or not isinstance(request, dict):
                    raise RuntimeError(f"Incomplete v2 case: {case['id']}")
                if case["vuln"] not in ("sqli", "xss") or not isinstance(case["family"], str):
                    raise RuntimeError(f"Invalid v2 vuln/family: {case['id']}")
                if case["expected_waf_outcome"] not in ("blocked", "allowed"):
                    raise RuntimeError(f"Invalid expected_waf_outcome: {case['id']}")
                if case["expected_app_effect"] not in ("executed", "not_executed", "none"):
                    raise RuntimeError(f"Invalid expected_app_effect: {case['id']}")
                if case["label"] == "benign" and case["expected_app_effect"] != "none":
                    raise RuntimeError(f"Benign case must have app effect none: {case['id']}")
                for field in ("method", "path", "params", "form", "headers", "transport"):
                    if field not in request:
                        raise RuntimeError(f"Missing request.{field}: {case['id']}")
                if case["vuln"] == "xss" and request["path"] != "/comment":
                    raise RuntimeError(f"XSS must target /comment: {case['id']}")
                control = case.get("control")
                if control is not None and (not isinstance(control, dict)
                                            or control.get("endpoint") != "/comment-escaped"
                                            or set(control.get("must_not", [])) != {"reflect", "execute"}):
                    raise RuntimeError(f"Invalid XSS control contract: {case['id']}")
                wire = dict(request)
                case["schema_version"] = 2
                case["_wire_request"] = wire
            else:
                wire = {key: case.get(key, default) for key, default in
                        (("method", "GET"), ("path", ""), ("params", []),
                         ("form", []), ("headers", {}), ("transport", None))}
                legacy_expected = case.get("expected_app")
                if legacy_expected not in ("executed", "blocked"):
                    raise RuntimeError(f"Case expected_app invalid: {case['id']}")
                family = ("benign.html" if case["label"] == "benign" else
                          "union" if "union" in case["id"] else
                          "tautology-n" if "mal" in case["id"] else
                          "legacy:" + case["id"].split("-")[0])
                case.update({
                    "schema_version": 1, "vuln": "sqli", "family": family,
                    "expected_waf_outcome": "blocked" if legacy_expected == "blocked" else "allowed",
                    "expected_app_effect": "none" if (legacy_expected == "blocked"
                                                       or case["label"] == "benign"
                                                       or case.get("control") == "none") else "executed",
                    "_wire_request": wire,
                })
            if wire["method"] not in ("GET", "POST"):
                raise RuntimeError(f"Case method invalid: {case['id']}")
            allowed_paths = ({"/search", "/product", "/login"} if case["vuln"] == "sqli"
                             else {"/comment"})
            if wire["path"] not in allowed_paths:
                raise RuntimeError(f"Case path not allowlisted for vuln: {case['id']}")
            for field in ("params", "form"):
                pairs = wire.get(field, [])
                if (not isinstance(pairs, list)
                        or any(not isinstance(pair, list) or len(pair) != 2
                               or not all(isinstance(value, str) for value in pair)
                               for pair in pairs)):
                    raise RuntimeError(f"{case['id']}.{field} must be ordered [key,value] pairs")
            if not isinstance(wire.get("headers", {}), dict):
                raise RuntimeError(f"{case['id']}.headers must be an object")
            if wire.get("transport") not in (None, "chunked"):
                raise RuntimeError(f"Unsupported transport: {case['id']}")
            if case["schema_version"] == 1 and case.get("control") not in (None, "none"):
                raise RuntimeError(f"Unsupported control policy: {case['id']}")
            cases.append(case)
    ids = [case["id"] for case in cases]
    if len(ids) != len(set(ids)):
        raise RuntimeError("Duplicate case id trong corpus")
    return cases


def corpus_paths(corpus_root, only_technique=None):
    folders = [only_technique] if only_technique else list(TECHNIQUES)
    if any(folder not in TECHNIQUES for folder in folders):
        raise RuntimeError(f"Corpus technique is not allowlisted: {folders!r}")
    root = Path(corpus_root).resolve()
    paths = []
    for folder in folders:
        technique_root = (root / folder).resolve()
        path = (technique_root / "cases.json").resolve()
        if technique_root.parent != root or path.parent != technique_root:
            raise RuntimeError(f"Corpus path escapes allowlisted technique folder: {path}")
        paths.append(path)
    return paths


def run_level(level, cases, out, metadata, env, skip_ml=False):
    """Chạy một PL: dựng lab, thực thi corpus, đối chiếu evidence, ghi kết quả."""
    env["CRS_PL"] = str(level)
    command(COMPOSE + ["up", "-d", "--wait", "--wait-timeout", "180"], env)
    engine = command(COMPOSE + ["exec", "-T", "waf-crs", "printenv",
                                "MODSEC_RULE_ENGINE"], env).strip()
    if engine != "On":
        raise RuntimeError("Blocking validation requires MODSEC_RULE_ENGINE=On")
    waf_port = loopback_port("waf-crs", 8080, env)
    app_port = loopback_port("web-app", 5000, env)
    ml_port = loopback_port("waf-ml", 5001, env)

    effective = command(COMPOSE + ["exec", "-T", "waf-crs", "sh", "-c",
                                   "nginx -v 2>&1; cat /etc/modsecurity.d/modsecurity.conf; "
                                   "cat /etc/modsecurity.d/owasp-crs/crs-setup.conf"], env)
    (out / f"pl{level}-effective-config.txt").write_text(effective, encoding="utf-8")

    # ML health ngay từ level này (stdin: model_version trong container).
    ml_health = json.loads(send(ml_port, {
        "method": "GET", "path": "/health",
        "params": [], "headers": {},
    }, f"{metadata['run_id']}-pl{level}-ml-health")["body"]) \
        if not skip_ml else {"status": "skipped", "model_version": None}
    metadata.setdefault("runtime", {})[str(level)] = {
        "waf_port": waf_port, "backend_port": app_port, "ml_port": ml_port,
        "ml_health": ml_health, "anomaly_inbound": 5,
    }
    if not skip_ml:
        artifact_script = (
            "import hashlib,json,os,pathlib; "
            "root=pathlib.Path(os.getenv('ML_MODEL_DIR','/app/artifacts')); "
            "has=lambda d:(d/'model.joblib').exists() and (d/'metrics.json').exists(); "
            "d=root if has(root) else root/'v1.1' if has(root/'v1.1') else None; "
            "assert d is not None, 'no ML artifacts in container'; "
            "print(json.dumps({'model_dir': str(d), "
            "'model_version': json.load(open(d/'metrics.json')).get('model_version'), "
            "'sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() "
            "for p in d.iterdir() if p.is_file()}}))"
        )
        artifact_info = json.loads(command(
            COMPOSE + ["exec", "-T", "waf-ml", "python", "-c", artifact_script], env))
        metadata["runtime"][str(level)]["ml_model_dir_container"] = artifact_info["model_dir"]
        metadata["runtime"][str(level)]["ml_model_version_container"] = artifact_info["model_version"]
        metadata["runtime"][str(level)]["ml_artifact_sha256"] = artifact_info["sha256"]
    (out / "metadata.json").write_text(json.dumps(metadata, indent=2,
                                                  ensure_ascii=False), encoding="utf-8")

    audit_offset = AUDIT.stat().st_size if AUDIT.exists() else 0
    app_offset = APP.stat().st_size if APP.exists() else 0
    ml_offset = ML_LOG.stat().st_size if ML_LOG.exists() else 0

    rows = []
    probe_ml = not skip_ml and metadata["crs_backend"] == "direct"
    for case in cases:
        correlation = f"{metadata['run_id']}-pl{level}-{case['id']}"
        request = wire_request(case)
        # Direct control luôn dùng transport chuẩn (Content-Length) để chứng
        # minh app thực thi payload gốc; chỉ đường qua WAF mới dùng transport
        # biến thể (chunked...) như corpus mô tả.
        direct = send(app_port, request, correlation + "-direct")
        escaped_direct = None
        if case["vuln"] == "xss":
            escaped_request = dict(request, path="/comment-escaped")
            escaped_direct = send(app_port, escaped_request, correlation + "-escaped-direct")
        via_waf = deliver(waf_port, request, correlation)
        via_ml = deliver(ml_port, request, correlation + "-ml") if probe_ml else None
        ml_text = " ".join(value for _, value in
                           (request.get("params", []) + request.get("form", []))) or ""
        rows.append({
            "run_id": metadata["run_id"], "paranoia_level": level,
            "case_id": case["id"], "technique": case["technique"],
            "vuln": case["vuln"], "family": case["family"],
            "schema_version": case["schema_version"], "label": case["label"],
            "expected_waf_outcome": case["expected_waf_outcome"],
            "expected_app_effect": case["expected_app_effect"],
            "transport": request.get("transport") or "standard",
            "request": case, "ml_text": ml_text,
            "ml": {},
            "ml_probe": probe_ml,
            "ml_http_status": None if not probe_ml else via_ml["status"],
            "ml_latency_ms": None if not probe_ml else via_ml["latency_ms"],
            "ml_response_body": "" if not probe_ml else via_ml["body"],
            "ml_error": None if not probe_ml else via_ml.get("error"),
            "direct_response": direct, "http_status": via_waf["status"],
            "escaped_direct_response": escaped_direct,
            "latency_ms": via_waf["latency_ms"],
            "wire": {"url": via_waf["raw_url"], "body": via_waf["raw_body"],
                     "transport": via_waf["transport"]},
            "response_body": via_waf["body"],
            "waf_error": via_waf.get("error"),
        })

    deadline = time.monotonic() + 30
    while True:
        audits, apps = lines_since(AUDIT, audit_offset), lines_since(APP, app_offset)
        ml_records = [] if skip_ml else lines_since(ML_LOG, ml_offset)
        audit_map = {audit_id(a): a for a in audits if audit_id(a)}
        app_map = {a.get("case_id"): a for a in apps}
        ml_map = {a.get("case_id"): a for a in ml_records}
        # Hoàn tất khi mỗi case có audit VÀ: nếu không bị chặn (400-series) thì
        # cuối cùng phải có app record; nếu bị chặn thì không cần đợi app.
        complete = all(
            ((f"{metadata['run_id']}-pl{level}-{r['case_id']}" in audit_map)
             or (r["http_status"] is None)
             or (r["waf_error"]))
            and ((r["http_status"] not in (200,) and r["http_status"] is not None)
                 or (f"{metadata['run_id']}-pl{level}-{r['case_id']}" in app_map))
            and (not probe_ml
                 or r["ml_error"]
                 or (f"{metadata['run_id']}-pl{level}-{r['case_id']}-ml" in ml_map
                     and (r["ml_http_status"] != 200
                          or f"{metadata['run_id']}-pl{level}-{r['case_id']}-ml" in app_map)))
            and (metadata["crs_backend"] != "ml"
                 or r["http_status"] != 200
                 or f"{metadata['run_id']}-pl{level}-{r['case_id']}" in ml_map)
            for r in rows)
        if complete or time.monotonic() > deadline:
            break
        time.sleep(0.3)

    for row in rows:
        cid = f"{metadata['run_id']}-pl{level}-{row['case_id']}"
        row["correlation_id"] = cid
        intended = row["label"] == "malicious"
        control_none = row["request"].get("control") == "none"
        expected_effect = False if (control_none or not intended) else True
        if row["vuln"] == "xss":
            payload = xss_payload(wire_request(row["request"]))
            valid_control, control_evidence = control_check_xss(
                row["direct_response"], row["escaped_direct_response"], payload,
                row["expected_app_effect"])
        else:
            valid_control, control_evidence = control_check(
                app_map.get(cid + "-direct"), expected_effect)
        row["direct_control_evidence"] = control_evidence
        audit = audit_map.get(cid)
        app_record = app_map.get(cid)
        row["app_evidence"] = app_record
        ml_cid = cid + "-ml"
        ml_record = ml_map.get(ml_cid) if probe_ml else None
        ml_app_record = app_map.get(ml_cid) if probe_ml else None
        hybrid_record = ml_map.get(cid) if metadata["crs_backend"] == "ml" else None
        row["hybrid_ml_evidence"] = hybrid_record
        if probe_ml:
            ml_result = {
                "decision": None, "outcome": "unclassified", "true_bypass": None,
                "http_status": row["ml_http_status"], "latency_ms": row["ml_latency_ms"],
                "app_evidence": ml_app_record,
            }
            if ml_record:
                ml_result.update(ml_evidence_fields(ml_record))
            ml_blocked = (row["ml_http_status"] == 403 and ml_record
                          and ml_record.get("decision") == "blocked"
                          and ml_app_record is None)
            ml_allowed = (row["ml_http_status"] == 200 and ml_record
                          and ml_record.get("decision") == "allowed"
                          and ml_app_record is not None)
            ml_effect = bool(ml_app_record and ml_app_record.get("semantic_effect"))
            if not valid_control:
                ml_result["outcome"] = "control_invalid"
            elif row["ml_error"] or row["ml_http_status"] is None:
                ml_result["outcome"] = "transport_error"
            elif not ml_record:
                ml_result["outcome"] = "missing_evidence"
            elif ml_blocked:
                ml_result.update(decision="blocked", outcome=(
                    "blocked" if intended else "benign_blocked"), true_bypass=False)
            elif ml_allowed:
                if row["vuln"] == "xss" and intended:
                    ml_outcome, ml_true_bypass = "execution_unverified", False
                elif intended and ml_effect:
                    ml_outcome, ml_true_bypass = "true_bypass", True
                elif intended and not ml_effect:
                    ml_outcome, ml_true_bypass = "pass_without_effect", False
                else:
                    ml_outcome, ml_true_bypass = "allowed", False
                ml_result.update(decision="allowed", outcome=ml_outcome,
                                 true_bypass=ml_true_bypass,
                                 semantic_effect=ml_effect)
                if row["vuln"] == "xss":
                    ml_result["reflected"] = xss_http_oracle(
                        row["ml_response_body"],
                        (row.get("escaped_direct_response") or {}).get("body", ""),
                        xss_payload(wire_request(row["request"])))
                    ml_result["execution_status"] = (
                        "execution_unverified" if intended else "not_applicable")
            row["ml"] = ml_record or {}
            row["ml_enforcement"] = ml_result
        rule_ids = []
        row["detected"] = False
        if row["waf_error"] or row["http_status"] is None:
            row["outcome"] = "transport_error"
            row["waf_decision"] = None
            continue
        if audit is None:
            row["outcome"] = "missing_audit"
            row["waf_decision"] = None
            continue
        transaction = audit["transaction"]
        rule_ids = sorted({str(m.get("details", {}).get("ruleId", ""))
                           for m in transaction.get("messages", [])} - {""})
        crs_blocked = (row["http_status"] == 403 and "949110" in rule_ids
                       and app_record is None)
        hybrid_ml_blocked = (row["http_status"] == 403 and hybrid_record
                             and hybrid_record.get("decision") == "blocked"
                             and app_record is None)
        blocked = crs_blocked or hybrid_ml_blocked
        allowed = (row["http_status"] == 200 and app_record is not None)
        if not (blocked or allowed):
            row["outcome"] = "unclassified"
            row["waf_decision"] = None
            continue
        families = rule_families(rule_ids)
        detected = ("sqli-rule" in families if row["vuln"] == "sqli"
                    else bool({"xss-rule", "sqli-rule"} & set(families)))
        effect = bool(app_record and app_record.get("semantic_effect")) \
            if app_record else False
        row.update(detected=detected, rule_ids=rule_ids, rule_families=families,
                   reached_app=app_record is not None,
                   semantic_effect=effect,
                   blocking_layer=("crs" if crs_blocked else
                                   "ml" if hybrid_ml_blocked else None))
        if not valid_control:
            row["outcome"] = "control_invalid"
            row["waf_decision"] = "blocked" if blocked else "allowed"
            continue
        row["waf_decision"] = "blocked" if blocked else "allowed"
        if row["vuln"] == "xss":
            escaped_body = (row.get("escaped_direct_response") or {}).get("body", "")
            reflected = xss_http_oracle(row.get("response_body", ""), escaped_body,
                                        xss_payload(wire_request(row["request"])))
            row["reflected"] = reflected
            row["true_bypass_xss"] = False
            if blocked:
                row["execution_status"] = "blocked"
                row["outcome"] = "blocked"
                row["true_bypass"] = False
            elif intended:
                row["execution_status"] = "execution_unverified"
                row["outcome"] = "execution_unverified"
                row["true_bypass"] = False
            else:
                row["execution_status"] = "not_applicable"
                row["outcome"] = "benign_blocked" if blocked else "allowed"
                row["true_bypass"] = False
        elif intended and blocked:
            row["outcome"], row["true_bypass"] = "blocked", False
        elif intended and allowed and detected:
            row["outcome"], row["true_bypass"] = "allowed_detected", False
        elif intended and allowed and not detected and effect:
            row["outcome"], row["true_bypass"] = "true_bypass", True
        elif intended and allowed and not detected and not effect:
            row["outcome"], row["true_bypass"] = "pass_without_effect", False
        elif not intended and blocked:
            row["outcome"], row["true_bypass"] = "benign_blocked", False
        elif not intended and allowed:
            row["outcome"], row["true_bypass"] = "allowed", False
            row.setdefault("passed", True)
        else:
            row["outcome"], row["true_bypass"] = "unclassified", None
    (out / f"pl{level}-audit.json").write_text(json.dumps(audits, indent=2),
                                               encoding="utf-8")
    (out / f"pl{level}-app.json").write_text(json.dumps(apps, indent=2,
                                                        ensure_ascii=False), encoding="utf-8")
    (out / f"pl{level}-ml.json").write_text(json.dumps(ml_records, indent=2,
                                                       ensure_ascii=False), encoding="utf-8")
    (out / f"pl{level}-responses.json").write_text(json.dumps(rows, indent=2,
                                                              ensure_ascii=False), encoding="utf-8")
    return rows, {"paranoia_level": level, **summarize(rows)}


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--levels", nargs="+", type=int, choices=[1, 2, 3], default=[1, 3])
    parser.add_argument("--technique", choices=TECHNIQUES, default=None)
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--skip-ml", action="store_true")
    parser.add_argument("--crs-backend", choices=("direct", "ml"), default="direct",
                        help="direct: CRS->app; ml: CRS->ML enforcement->app")
    args = parser.parse_args()
    if args.skip_ml and args.crs_backend == "ml":
        parser.error("--skip-ml cannot be combined with --crs-backend ml")

    corpus_root = Path(args.corpus)
    cases = load_corpus(corpus_root, args.technique)
    corpus_files = [str(path) for path in corpus_paths(corpus_root, args.technique)]

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    out = ROOT / "results/raw/experiments" / run_id
    out.mkdir(parents=True)

    env = os.environ.copy()
    env["CRS_BACKEND"] = ("http://waf-ml:5001" if args.crs_backend == "ml"
                          else "http://web-app:5000")
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
                                capture_output=True, encoding="utf-8").stdout.strip() or None
    except Exception:
        commit = None

    metadata = {
        "run_id": run_id, "levels": args.levels, "technique": args.technique,
        "crs_backend": args.crs_backend,
        "corpus_files": corpus_files,
        "corpus_sha256": {p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
                          for p in corpus_files},
        "commit_hash": commit, "host": platform.platform(),
        "python_runner": platform.python_version(),
        "docker": command(["docker", "version"]),
        "compose": command(["docker", "compose", "version"]),
        "anomaly_inbound": 5, "seed": None,
        "ml_mode": "ML-only probe in direct runs; hybrid decision in RUN-B"
        if not args.skip_ml else "skipped",
        "ml_probe_policy": "RUN-A direct runs include standalone ML; RUN-B hybrid runs omit duplicate ML-only probe",
        "source_sha256": {
            path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
            for path in ("docker-compose.yml", "web-app/app.py",
                         "scripts/run_experiment.py", "scripts/sweep_thresholds.py",
                         "docker/waf-ml/Dockerfile", "waf-ml/requirements.txt",
                         "waf-ml/app.py", "waf-ml/server.py", "waf-ml/train.py",
                         "waf-ml/build_dataset.py",
                         "dataset/bypass/README.md", "dataset/bypass/validate_corpus.py",
                         "scripts/verify_xss_execution.py")},
    }
    metadata["images"] = command(COMPOSE + ["images", "--format", "json"], env)
    (out / "metadata.json").write_text(json.dumps(metadata, indent=2,
                                                  ensure_ascii=False), encoding="utf-8")

    all_rows, summaries, technique_summaries = [], [], []
    for level in args.levels:
        level_rows, summary = run_level(level, cases, out, metadata, env, skip_ml=args.skip_ml)
        all_rows.extend(level_rows)
        summary["by_technique"] = summarize_by_technique(level_rows)
        summary["cases"] = [
            {"id": r["case_id"], "outcome": r["outcome"],
             "vuln": r.get("vuln", "sqli"), "family": r.get("family"),
             "waf_decision": r.get("waf_decision"), "detected": r.get("detected"),
             "reflected": r.get("reflected"),
             "execution_status": r.get("execution_status"),
             "true_bypass_xss": r.get("true_bypass_xss"),
             "semantic_effect": r.get("semantic_effect"),
             "http_status": r.get("http_status"),
             "ml_label": (r.get("ml") or {}).get("label"),
             "ml_score": (r.get("ml") or {}).get("score"),
             "ml_decision": (r.get("ml_enforcement") or {}).get("decision"),
             "ml_outcome": (r.get("ml_enforcement") or {}).get("outcome"),
             "ml_true_bypass": (r.get("ml_enforcement") or {}).get("true_bypass"),
             "rule_ids": r.get("rule_ids", []), "transport": r.get("transport")}
            for r in level_rows]
        summaries.append(summary)
        technique_summaries.append(summary["by_technique"])
    pending = []
    for row in all_rows:
        if (row.get("vuln") != "xss" or row.get("label") != "malicious"
                or row.get("outcome") != "execution_unverified"):
            continue
        configurations = []
        if metadata["crs_backend"] == "ml":
            if row.get("waf_decision") == "allowed":
                configurations.append("hybrid")
        else:
            if row.get("waf_decision") == "allowed":
                configurations.append("crs_only")
            if (row.get("ml_enforcement") or {}).get("decision") == "allowed":
                configurations.append("ml_only")
        for configuration in configurations:
            reflected = row.get("reflected", False)
            if configuration == "ml_only":
                reflected = (row.get("ml_enforcement") or {}).get("reflected", False)
            pending.append({
                "run_id": run_id, "case_id": row["case_id"],
                "configuration": configuration,
                "paranoia_level": row["paranoia_level"],
                "reflected": reflected,
            })
    (out / "pending_browser_verification.json").write_text(
        json.dumps(pending, indent=2, ensure_ascii=False), encoding="utf-8")
    (out / "results.json").write_text(json.dumps(all_rows, indent=2,
                                                 ensure_ascii=False), encoding="utf-8")
    (out / "summary.json").write_text(json.dumps({
        "run_id": run_id, "by_level": summaries,
        "by_technique": technique_summaries}, indent=2, ensure_ascii=False),
        encoding="utf-8")
    with (out / "results.csv").open("w", newline="", encoding="utf-8") as stream:
        fields = ["run_id", "paranoia_level", "case_id", "vuln", "family",
                  "technique", "label",
                  "outcome", "waf_decision", "detected", "reached_app",
                  "semantic_effect", "true_bypass", "blocking_layer",
                  "reflected", "execution_status", "true_bypass_xss",
                  "http_status", "latency_ms", "rule_ids", "rule_families",
                  "ml_label", "ml_score", "ml_model_version",
                  "ml_decision", "ml_outcome", "ml_execution_status",
                  "ml_reflected", "ml_true_bypass_xss", "ml_true_bypass",
                  "ml_attack_score", "ml_threshold",
                  "ml_http_status", "ml_latency_ms", "transport"]
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in all_rows:
            writer.writerow({
                **{k: row.get(k) for k in fields if k not in
                   ("ml_label", "ml_score", "ml_model_version")},
                "ml_label": (row.get("ml") or {}).get("label"),
                "ml_score": (row.get("ml") or {}).get("score"),
                "ml_model_version": (row.get("ml") or {}).get("model_version"),
                "ml_decision": (row.get("ml_enforcement") or {}).get("decision"),
                "ml_outcome": (row.get("ml_enforcement") or {}).get("outcome"),
                "ml_execution_status": (row.get("ml_enforcement") or {}).get("execution_status"),
                "ml_reflected": (row.get("ml_enforcement") or {}).get("reflected"),
                "ml_true_bypass_xss": (row.get("ml_enforcement") or {}).get("true_bypass_xss"),
                "ml_true_bypass": (row.get("ml_enforcement") or {}).get("true_bypass"),
                "ml_attack_score": (row.get("ml_enforcement") or {}).get("attack_score"),
                "ml_threshold": (row.get("ml_enforcement") or {}).get("threshold"),
            })
    compact = [{"paranoia_level": item["paranoia_level"],
                "sqli": item["by_vuln"].get("sqli"),
                "xss": item["by_vuln"].get("xss"),
                "pending_browser_verification": item["execution_unverified"]}
               for item in summaries]
    print(json.dumps({"run_id": run_id, "levels": args.levels,
                      "summaries": compact}, ensure_ascii=False), flush=True)
    print("Evidence: " + out.relative_to(ROOT).as_posix(), flush=True)


if __name__ == "__main__":
    main()
