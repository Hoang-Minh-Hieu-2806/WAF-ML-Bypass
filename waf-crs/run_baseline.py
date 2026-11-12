"""Run the CRS owner's PL1/2/3 baseline; all requests stay on loopback.

Python standard library only. Shared experiment runner/ML remain separate tasks.
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
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["docker", "compose", "-f", str(ROOT / "docker/waf-crs/compose.yml")]
AUDIT = ROOT / "logs/waf/crs/audit.log"
APP = ROOT / "logs/application/crs/app.jsonl"


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


def send(port, request, correlation):
    query = urlencode([tuple(pair) for pair in request.get("params", [])])
    url = f"http://127.0.0.1:{port}" + request["path"] + ("?" + query if query else "")
    data = urlencode([tuple(pair) for pair in request["form"]]).encode() if "form" in request else None
    headers = {"Host": f"localhost:{port}", "X-Lab-Case-ID": correlation, "User-Agent": "crs-baseline/1.0",
               "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    start = time.perf_counter()
    try:
        response = CLIENT.open(Request(url, data=data, headers=headers,
                                       method=request["method"]), timeout=10)
    except HTTPError as error:
        response = error
    with response:
        body = response.read().decode("utf-8", errors="replace")
        status = response.code
    return {"status": status, "body": body,
            "latency_ms": round((time.perf_counter() - start) * 1000, 3),
            "raw_url": url, "raw_body": data.decode() if data is not None else ""}


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
            # An audit record being written can be incomplete; caller retries.
            continue
    return records


def audit_id(record):
    headers = record.get("transaction", {}).get("request", {}).get("headers", {})
    return next((v for k, v in headers.items() if k.lower() == "x-lab-case-id"), None)


def summarize(rows):
    malicious = [r for r in rows if r["label"] == "malicious"]
    benign = [r for r in rows if r["label"] == "benign"]
    blocked = sum(r["waf_decision"] == "blocked" for r in malicious)
    detected = sum(r["detected"] for r in malicious)
    missed = len(malicious) - detected
    fp = sum(r["waf_decision"] == "blocked" for r in benign)
    bypass = sum(r["true_bypass"] for r in malicious)
    pct = lambda count, total: round(100 * count / total, 3) if total else None
    return {"malicious_total": len(malicious), "benign_total": len(benign),
            "malicious_detected": detected, "malicious_blocked": blocked,
            "malicious_reached_app": sum(r["reached_app"] for r in malicious),
            "malicious_semantic_effect": sum(r["semantic_effect"] for r in malicious),
            "true_bypasses": bypass, "false_negatives_detection": missed,
            "benign_blocked": fp, "detection_rate_pct": pct(detected, len(malicious)),
            "block_rate_pct": pct(blocked, len(malicious)),
            "fnr_detection_pct": pct(missed, len(malicious)),
            "fpr_blocking_pct": pct(fp, len(benign)),
            "bypass_rate_pct": pct(bypass, len(malicious))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--levels", nargs="+", type=int, choices=[1, 2, 3], default=[1, 2, 3])
    args = parser.parse_args()
    corpus_path = ROOT / "waf-crs/baseline.json"
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    out = ROOT / "results/raw/crs" / run_id
    out.mkdir(parents=True)
    for log in (AUDIT, APP):
        log.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    waf_port = int(env.get("CRS_PORT", "18081"))
    app_port = int(env.get("CRS_BACKEND_PORT", "18080"))
    metadata = {"run_id": run_id, "started_utc": datetime.now(timezone.utc).isoformat(),
                "host": platform.platform(), "python_runner": platform.python_version(),
                "corpus_sha256": hashlib.sha256(corpus_path.read_bytes()).hexdigest(),
                "levels": args.levels, "anomaly_inbound": 5, "response_inspection": False,
                "request_host": "localhost", "seed": None, "ml_model": None,
                "docker": command(["docker", "version"]),
                "compose": command(["docker", "compose", "version"])}
    for filename in ("docker/waf-crs/Dockerfile", "docker/waf-crs/Dockerfile.backend",
                     "docker/waf-crs/compose.yml", "docker/waf-crs/init-audit.sh",
                     "waf-crs/test_backend.py", "waf-crs/run_baseline.py"):
        metadata.setdefault("source_sha256", {})[filename] = hashlib.sha256((ROOT / filename).read_bytes()).hexdigest()
    (out / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    command(COMPOSE + ["build"], env)
    all_rows, summaries = [], []
    for level in args.levels:
        env["CRS_PL"] = str(level)
        command(COMPOSE + ["up", "-d", "--wait", "--wait-timeout", "120"], env)
        waf_cid = command(COMPOSE + ["ps", "-q", "waf-crs"], env).strip()
        app_cid = command(COMPOSE + ["ps", "-q", "crs-test-backend"], env).strip()
        (out / f"pl{level}-compose.json").write_text(command(COMPOSE + ["config", "--format", "json"], env), encoding="utf-8")
        # Save effective generated engine + CRS config, not just env intent.
        config = command(COMPOSE + ["exec", "-T", "waf-crs", "sh", "-c",
                         "nginx -v 2>&1; cat /etc/modsecurity.d/modsecurity.conf; cat /etc/modsecurity.d/owasp-crs/crs-setup.conf"], env)
        (out / f"pl{level}-effective-config.txt").write_text(config, encoding="utf-8")
        (out / f"pl{level}-containers.json").write_text(command(["docker", "inspect", waf_cid, app_cid]), encoding="utf-8")
        (out / f"pl{level}-backend-version.txt").write_text(command(COMPOSE + ["exec", "-T", "crs-test-backend", "python", "-c", "import sys,sqlite3; print(sys.version); print('SQLite',sqlite3.sqlite_version)"], env), encoding="utf-8")
        audit_offset = AUDIT.stat().st_size if AUDIT.exists() else 0
        app_offset = APP.stat().st_size if APP.exists() else 0
        rows = []
        for case in corpus:
            correlation = f"{run_id}-pl{level}-{case['id']}"
            direct = send(app_port, case["request"], correlation + "-direct")
            direct_app = json.loads(direct["body"])
            intended = case["label"] == "malicious"
            if direct["status"] != 200 or direct_app.get("semantic_effect") != intended or direct_app.get("sql_error"):
                raise RuntimeError(f"Invalid corpus control {case['id']}: {direct_app}")
            via_waf = send(waf_port, case["request"], correlation)
            rows.append({"case_id": case["id"], "correlation_id": correlation,
                         "technique": case["technique"], "label": case["label"],
                         "paranoia_level": level, "http_status": via_waf["status"],
                         "latency_ms": via_waf["latency_ms"], "request": case["request"],
                         "wire": {"url": via_waf["raw_url"], "body": via_waf["raw_body"]},
                         "response_body": via_waf["body"], "direct_control": direct_app})
        deadline = time.monotonic() + 10
        while True:
            audits = lines_since(AUDIT, audit_offset)
            apps = lines_since(APP, app_offset)
            audit_map = {audit_id(r): r for r in audits if audit_id(r)}
            app_map = {r.get("case_id"): r for r in apps}
            if all(r["correlation_id"] in audit_map for r in rows):
                break
            if time.monotonic() > deadline:
                raise RuntimeError("Missing correlated audit logs; run incomplete: " + str(out))
            time.sleep(0.2)
        for row in rows:
            audit = audit_map[row["correlation_id"]]
            transaction = audit["transaction"]
            messages = transaction.get("messages", [])
            rule_ids = sorted({str(m.get("details", {}).get("ruleId", "")) for m in messages} - {""})
            app = app_map.get(row["correlation_id"])
            audit_status = int(transaction["response"]["http_code"])
            if audit_status != row["http_status"]:
                raise RuntimeError("Audit/HTTP mismatch: " + row["case_id"])
            blocked = row["http_status"] == 403 and "949110" in rule_ids and app is None
            allowed = row["http_status"] == 200 and app is not None
            if not (blocked or allowed):
                raise RuntimeError(f"Unclassified outcome {row['case_id']}: {row['http_status']}, {rule_ids}, app={app is not None}")
            row.update({"waf_decision": "blocked" if blocked else "allowed",
                        "detected": any(r.startswith("942") for r in rule_ids),
                        "rule_ids": rule_ids, "messages": messages,
                        "reached_app": app is not None, "app_evidence": app,
                        "semantic_effect": bool(app and app.get("semantic_effect"))})
            # Strict detection-based bypass: allowed, no SQLi detection, effect proven.
            row["true_bypass"] = (row["label"] == "malicious" and allowed
                                  and not row["detected"] and row["semantic_effect"])
        (out / f"pl{level}-audit.json").write_text(json.dumps(audits, indent=2), encoding="utf-8")
        metadata.setdefault("runtime_producer", {})[str(level)] = audit_map[rows[0]["correlation_id"]]["transaction"]["producer"]
        (out / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        (out / f"pl{level}-app.json").write_text(json.dumps(apps, indent=2, ensure_ascii=False), encoding="utf-8")
        (out / f"pl{level}-container.log").write_text(command(COMPOSE + ["logs", "--no-color"], env), encoding="utf-8")
        summaries.append({"paranoia_level": level, **summarize(rows)})
        all_rows.extend(rows)
        print(json.dumps(summaries[-1]), flush=True)
    (out / "results.json").write_text(json.dumps(all_rows, indent=2, ensure_ascii=False), encoding="utf-8")
    (out / "summary.json").write_text(json.dumps(summaries, indent=2), encoding="utf-8")
    with (out / "results.csv").open("w", newline="", encoding="utf-8") as stream:
        fields = ["case_id", "technique", "label", "paranoia_level", "waf_decision", "http_status",
                  "detected", "reached_app", "semantic_effect", "true_bypass", "rule_ids", "latency_ms"]
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_rows)
    print("Evidence: " + str(out), flush=True)


if __name__ == "__main__":
    main()
