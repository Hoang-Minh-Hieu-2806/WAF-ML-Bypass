"""T03 — Experimental runner cho corpus bypass (docs/interfaces.md §1).

Đối tượng đo: CRS PL1–PL3 + ML-WAF (chế độ đánh giá, POST /score) trên cùng
corpus 4 nhóm kỹ thuật; chuỗi evidence mỗi case:
request -> CRS decision -> ML score -> app behavior (direct control oracle).

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
  ML:
    "TP/FP" chỉ nghĩa ở tầng classifier (app không gọi ML block).
    Do đó không bao giờ gộp ML vào block-rate CRS end-to-end.

Evidence: results/raw/experiments/<run-id>/ — plN-{audit,app,responses}.json,
results.json aggiuntivo, results.csv, summary.json, metadata.json (run id,
UTC, commit hash, corpus sha256, source sha256, image lists, ML model version,
effective CRS config theo PL). output mỗi run nằm trong thư mục run riêng,
không đè evidence cũ.

Lệnh (PowerShell từ root repo):
  $env:PYTHONUTF8='1'
  python scripts/run_experiment.py --levels 1 2 3
  python scripts/run_experiment.py --technique hpp --levels 1
  python scripts/run_experiment.py --skip-ml
"""
import argparse
import csv
import hashlib
import json
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
DEFAULT_CORPUS = ROOT / "dataset/bypass"
TECHNIQUES = ("hpp", "double-encoding", "case-comment", "parsing-discrepancy")


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


def ml_score(ml_base, text):
    request = Request(ml_base + "/score",
                      data=json.dumps({"text": text}).encode("utf-8"),
                      headers={"Content-Type": "application/json"}, method="POST")
    try:
        with CLIENT.open(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        return {"label": None, "score": None, "model_version": None,
                "error": f"{type(exc).__name__}: {exc}"}


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


def summarize(rows):
    malicious = [r for r in rows if r["label"] == "malicious"]
    benign = [r for r in rows if r["label"] == "benign"]
    valid_mal = [r for r in malicious if r["outcome"] != "control_invalid"]
    valid_ben = [r for r in benign if r["outcome"] != "control_invalid"]
    detected = sum(r.get("detected") for r in valid_mal)
    blocked = sum(r.get("waf_decision") == "blocked" for r in valid_mal)
    bypass = sum(r.get("true_bypass") is True for r in valid_mal)
    fp = sum(r.get("waf_decision") == "blocked" for r in valid_ben)
    pct = lambda count, total: round(100 * count / total, 2) if total else None
    return {
        "malicious_total": len(valid_mal), "benign_total": len(valid_ben),
        "malicious_detected": detected, "malicious_blocked": blocked,
        "true_bypasses": bypass, "benign_blocked": fp,
        "detection_rate_pct": pct(detected, len(valid_mal)),
        "block_rate_pct": pct(blocked, len(valid_mal)),
        "fnr_detection_pct": pct(len(valid_mal) - detected, len(valid_mal)),
        "fpr_blocking_pct": pct(fp, len(valid_ben)),
        "bypass_rate_pct": pct(bypass, len(valid_mal)),
        "ml_tp": sum((r.get("ml") or {}).get("label") == "malicious" for r in valid_mal),
        "ml_fp": sum((r.get("ml") or {}).get("label") == "malicious" for r in valid_ben),
        "inconclusive": sum(r.get("outcome") in ("pass_without_effect",)
                            for r in rows),
        "incomplete": sum(r.get("outcome") in ("transport_error", "missing_audit",
                                               "unclassified") for r in rows),
        "control_invalid_total": sum(r.get("outcome") == "control_invalid" for r in rows),
    }


def summarize_by_technique(rows):
    out = {}
    for technique in sorted({r["technique"] for r in rows}):
        subset = [r for r in rows if r["technique"] == technique]
        payload = summarize(subset)
        payload["by_outcome"] = {}
        for outcome in ("blocked", "benign_blocked", "allowed", "allowed_detected",
                        "pass_without_effect", "true_bypass", "control_invalid",
                        "transport_error", "missing_audit", "unclassified"):
            matches = sum(1 for r in subset if r.get("outcome") == outcome)
            if matches:
                payload["by_outcome"][outcome] = matches
        out[technique] = payload
    return out


def load_corpus(corpus_root, only_technique=None):
    cases = []
    folders = [only_technique] if only_technique else list(TECHNIQUES)
    for folder in folders:
        path = Path(corpus_root) / folder / "cases.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        for case in data:
            if case["technique"] != folder:
                raise RuntimeError(f"Corpus technique mismatch: {case['id']} placed in {folder}")
            if case["label"] not in ("benign", "malicious"):
                raise RuntimeError(f"Case label invalid: {case['id']}")
            if case["method"] not in ("GET", "POST"):
                raise RuntimeError(f"Case method invalid: {case['id']}")
            if case["path"] not in ("/search", "/product", "/login"):
                raise RuntimeError(f"Case path không thuộc lab: {case['id']}")
            cases.append(case)
    ids = [case["id"] for case in cases]
    if len(ids) != len(set(ids)):
        raise RuntimeError("Duplicate case id trong corpus")
    return cases


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
    ml_base = f"http://127.0.0.1:{ml_port}"

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
        ml_model_version_container = command(COMPOSE + ["exec", "-T", "waf-ml",
                                                        "python", "-c",
            "import json; print(json.load(open('/app/artifacts/metrics.json'))"
            ".get('model_version'))"], env).strip()
        metadata["runtime"][str(level)]["ml_model_version_container"] = ml_model_version_container
    (out / "metadata.json").write_text(json.dumps(metadata, indent=2,
                                                  ensure_ascii=False), encoding="utf-8")

    audit_offset = AUDIT.stat().st_size if AUDIT.exists() else 0
    app_offset = APP.stat().st_size if APP.exists() else 0

    rows = []
    for case in cases:
        correlation = f"{metadata['run_id']}-pl{level}-{case['id']}"
        # Direct control luôn dùng transport chuẩn (Content-Length) để chứng
        # minh app thực thi payload gốc; chỉ đường qua WAF mới dùng transport
        # biến thể (chunked...) như corpus mô tả.
        direct = send(app_port, case, correlation + "-direct")
        via_waf = deliver(waf_port, case, correlation)
        ml_text = " ".join(value for _, value in
                           (case.get("params", []) + case.get("form", []))) or ""
        rows.append({
            "run_id": metadata["run_id"], "paranoia_level": level,
            "case_id": case["id"], "technique": case["technique"],
            "label": case["label"], "transport": case.get("transport") or "standard",
            "request": case, "ml_text": ml_text,
            "ml": {} if skip_ml else ml_score(ml_base, ml_text),
            "direct_response": direct, "http_status": via_waf["status"],
            "latency_ms": via_waf["latency_ms"],
            "wire": {"url": via_waf["raw_url"], "body": via_waf["raw_body"],
                     "transport": via_waf["transport"]},
            "response_body": via_waf["body"],
            "waf_error": via_waf.get("error"),
        })

    deadline = time.monotonic() + 30
    while True:
        audits, apps = lines_since(AUDIT, audit_offset), lines_since(APP, app_offset)
        audit_map = {audit_id(a): a for a in audits if audit_id(a)}
        app_map = {a.get("case_id"): a for a in apps}
        # Hoàn tất khi mỗi case có audit VÀ: nếu không bị chặn (400-series) thì
        # cuối cùng phải có app record; nếu bị chặn thì không cần đợi app.
        complete = all(
            ((f"{metadata['run_id']}-pl{level}-{r['case_id']}" in audit_map)
             or (r["http_status"] is None)
             or (r["waf_error"]))
            and ((r["http_status"] not in (200,) and r["http_status"] is not None)
                 or (f"{metadata['run_id']}-pl{level}-{r['case_id']}" in app_map))
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
        valid_control, control_evidence = control_check(
            app_map.get(cid + "-direct"), expected_effect)
        row["direct_control_evidence"] = control_evidence
        audit = audit_map.get(cid)
        app_record = app_map.get(cid)
        row["app_evidence"] = app_record
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
        blocked = (row["http_status"] == 403 and "949110" in rule_ids
                   and app_record is None)
        allowed = (row["http_status"] == 200 and app_record is not None)
        if not (blocked or allowed):
            row["outcome"] = "unclassified"
            row["waf_decision"] = None
            continue
        detected = any(rule.startswith("942") for rule in rule_ids)
        effect = bool(app_record and app_record.get("semantic_effect")) \
            if app_record else False
        row.update(detected=detected, rule_ids=rule_ids,
                   reached_app=app_record is not None,
                   semantic_effect=effect)
        if not valid_control:
            row["outcome"] = "control_invalid"
            row["waf_decision"] = "blocked" if blocked else "allowed"
            continue
        row["waf_decision"] = "blocked" if blocked else "allowed"
        if intended and blocked:
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
        # ML là scoring API không block; tp ở tầng classifier.
    (out / f"pl{level}-audit.json").write_text(json.dumps(audits, indent=2),
                                               encoding="utf-8")
    (out / f"pl{level}-app.json").write_text(json.dumps(apps, indent=2,
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
    args = parser.parse_args()

    corpus_root = Path(args.corpus)
    cases = load_corpus(corpus_root, args.technique)
    corpus_files = [str(ROOT / "dataset/bypass" / f / "cases.json") for f in
                    ([args.technique] if args.technique else list(TECHNIQUES))]

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    out = ROOT / "results/raw/experiments" / run_id
    out.mkdir(parents=True)

    env = os.environ.copy()
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
                                capture_output=True, encoding="utf-8").stdout.strip() or None
    except Exception:
        commit = None

    metadata = {
        "run_id": run_id, "levels": args.levels, "technique": args.technique,
        "corpus_files": corpus_files,
        "corpus_sha256": {p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
                          for p in corpus_files},
        "commit_hash": commit, "host": platform.platform(),
        "python_runner": platform.python_version(),
        "docker": command(["docker", "version"]),
        "compose": command(["docker", "compose", "version"]),
        "anomaly_inbound": 5, "seed": None,
        "ml_mode": "evaluation-only (scoring API; không block end-to-end)" if not args.skip_ml
        else "skipped",
        "source_sha256": {
            path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
            for path in ("docker-compose.yml", "web-app/app.py",
                         "scripts/run_experiment.py",
                         "dataset/bypass/README.md")},
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
             "waf_decision": r.get("waf_decision"), "detected": r.get("detected"),
             "semantic_effect": r.get("semantic_effect"),
             "http_status": r.get("http_status"),
             "ml_label": (r.get("ml") or {}).get("label"),
             "ml_score": (r.get("ml") or {}).get("score"),
             "rule_ids": r.get("rule_ids", []), "transport": r.get("transport")}
            for r in level_rows]
        summaries.append(summary)
        technique_summaries.append(summary["by_technique"])
    (out / "results.json").write_text(json.dumps(all_rows, indent=2,
                                                 ensure_ascii=False), encoding="utf-8")
    (out / "summary.json").write_text(json.dumps({
        "run_id": run_id, "by_level": summaries,
        "by_technique": technique_summaries}, indent=2, ensure_ascii=False),
        encoding="utf-8")
    with (out / "results.csv").open("w", newline="", encoding="utf-8") as stream:
        fields = ["run_id", "paranoia_level", "case_id", "technique", "label",
                  "outcome", "waf_decision", "detected", "reached_app",
                  "semantic_effect", "true_bypass", "http_status", "latency_ms",
                  "rule_ids", "ml_label", "ml_score", "ml_model_version",
                  "transport"]
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in all_rows:
            writer.writerow({
                **{k: row.get(k) for k in fields if k not in
                   ("ml_label", "ml_score", "ml_model_version")},
                "ml_label": (row.get("ml") or {}).get("label"),
                "ml_score": (row.get("ml") or {}).get("score"),
                "ml_model_version": (row.get("ml") or {}).get("model_version"),
            })
    print(json.dumps({"run_id": run_id, "levels": args.levels,
                      "summaries": summaries}, ensure_ascii=False), flush=True)
    print("Evidence: " + str(out), flush=True)


if __name__ == "__main__":
    main()
