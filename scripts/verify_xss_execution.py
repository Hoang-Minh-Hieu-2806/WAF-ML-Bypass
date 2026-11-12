"""Playwright app-control (R6) and per-path WAF browser oracle (R7) for the local lab."""

import argparse
import csv
import hashlib
from http.client import HTTPConnection
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import run_experiment as runner  # noqa: E402


def base_url(config, env):
    if config == "app_control":
        service, port = "web-app", 5000
    elif config == "crs_only" or config == "hybrid":
        service, port = "waf-crs", 8080
    elif config == "ml_only":
        service, port = "waf-ml", 5001
    else:
        raise ValueError(f"Unsupported configuration: {config}")
    host_port = runner.loopback_port(service, port, env)
    return f"http://127.0.0.1:{host_port}"


def request_url(base, request):
    query = urlencode([tuple(pair) for pair in request.get("params", [])])
    return base + request["path"] + ("?" + query if query else "")


def marker_for(request):
    text = runner.xss_payload(request)
    match = re.search(r"document\.title\s*=\s*(['\"])(.*?)\1", text, re.IGNORECASE)
    return match.group(2) if match else None


def check_page(browser, url, expected_effect, request_body=None, request_headers=None,
               timeout_ms=1000):
    page = browser.new_page()
    initial_title = page.title()
    dialogs = []
    page.on("dialog", lambda dialog: (dialogs.append(dialog.type), dialog.accept()))
    response = None
    error = None
    try:
        if request_body is None:
            response = page.goto(url, wait_until="load", timeout=15000)
            status = response.status if response else None
            body = response.text() if response else ""
        else:
            parsed = urlsplit(url)
            connection = HTTPConnection(parsed.hostname, parsed.port or 80, timeout=15)
            try:
                target = parsed.path + (("?" + parsed.query) if parsed.query else "")
                connection.request("GET", target, body=request_body,
                                   headers=request_headers or {})
                response = connection.getresponse()
                status = response.status
                body = response.read().decode("utf-8", errors="replace")
            finally:
                connection.close()
            page.set_content(body, wait_until="load", timeout=15000)
        page.wait_for_timeout(timeout_ms)
        title = page.title()
        marker = expected_effect
        title_signal = title == marker if marker else title != initial_title
        executed = title_signal or bool(dialogs)
        return {
            "page": page,
            "http_status": status,
            "response_body": body,
            "title": title,
            "executed": executed,
            "execution_signal": "dialog" if dialogs else ("title_change" if executed else "none"),
            "expected_title": marker,
            "browser_error": None,
        }
    except Exception as exc:  # retain a per-case browser failure in evidence
        error = f"{type(exc).__name__}: {exc}"
        return {"page": page, "http_status": response.status if response else None,
                "response_body": "",
                "title": page.title(), "executed": False,
                "execution_signal": "none", "browser_error": error}


def corpus_digest():
    digest = hashlib.sha256()
    for path in runner.corpus_paths(runner.DEFAULT_CORPUS):
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def app_control_cases(cases):
    malicious = [case for case in cases if case["vuln"] == "xss" and case["label"] == "malicious"]
    benign = [case for case in cases if case["vuln"] == "xss" and case["label"] == "benign"]
    # Representative controls: ordinary HTML and comparison-text/duplicate handling.
    selected_benign = [next(case for case in benign if case["id"] == wanted)
                       for wanted in ("xss-pd-ben-001", "xss-hpp-ben-001")]
    return malicious + selected_benign


def write_evidence(records, target_dir):
    target_dir.mkdir(parents=True, exist_ok=True)
    path = target_dir / "evidence.json"
    path.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Browser evidence: {path.relative_to(ROOT).as_posix()}")


def verify_app_control(cases, output_dir, env):
    direct_base = base_url("app_control", env)
    records = []
    failures = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        for case in app_control_cases(cases):
            request = runner.wire_request(case)
            primary_url = request_url(direct_base, request)
            expected = case["expected_app_effect"]
            marker = marker_for(request) if expected == "executed" else None
            get_body = (urlencode([tuple(pair) for pair in request.get("form", [])]).encode("ascii")
                        if request["method"] == "GET" and request.get("form") else None)
            get_headers = request.get("headers", {})
            if get_body is not None and not any(key.lower() == "content-type" for key in get_headers):
                get_headers = {**get_headers, "Content-Type": "application/x-www-form-urlencoded"}
            primary = check_page(browser, primary_url, marker, get_body, get_headers)
            control_request = dict(request, path="/comment-escaped")
            control_url = request_url(direct_base, control_request)
            control = check_page(browser, control_url, None, get_body, get_headers)
            text = runner.xss_payload(request)
            reflected = runner.xss_http_oracle(
                primary["response_body"], control["response_body"], text)
            expected_executed = expected == "executed"
            valid = (primary["http_status"] == 200 and control["http_status"] == 200
                     and primary["executed"] == expected_executed
                     and not control["executed"])
            if expected == "executed" and not reflected:
                valid = False
            if primary["browser_error"] or control["browser_error"]:
                valid = False
            screenshot = output_dir / f"{case['id']}.png"
            primary["page"].screenshot(path=str(screenshot), full_page=True)
            records.append({
                "case_id": case["id"], "verification_mode": "app_control",
                "configuration": "app_control", "paranoia_level": None,
                "endpoint": request["path"], "control_endpoint": "/comment-escaped",
                "test_timestamp": datetime.now(timezone.utc).isoformat(),
                "http_status": primary["http_status"], "control_http_status": control["http_status"],
                "reflected": reflected, "executed": primary["executed"],
                "control_executed": control["executed"],
                "execution_status": "executed" if primary["executed"] else "not_executed",
                "execution_signal": primary["execution_signal"],
                "browser_error": primary["browser_error"] or control["browser_error"],
                "screenshot_path": screenshot.relative_to(ROOT).as_posix(),
                "expected_app_effect": expected, "valid": valid,
                "commit_hash": runner.command(["git", "rev-parse", "HEAD"]).strip(),
                "corpus_sha256": corpus_digest(), "run_id": None,
            })
            primary["page"].close()
            control["page"].close()
            if not valid:
                failures.append(case["id"])
            print(f"{case['id']}: {records[-1]['execution_status']} "
                  f"control={'safe' if not control['executed'] else 'executed'} valid={valid}")
        browser.close()
    write_evidence(records, output_dir)
    return failures


def verify_waf_path(cases, pending_file, output_dir, env, config, level):
    pending = json.loads(pending_file.read_text(encoding="utf-8"))
    if not isinstance(pending, list):
        raise RuntimeError("pending_browser_verification.json must contain an array")
    items = [item for item in pending
             if item.get("configuration") == config and item.get("paranoia_level") == level]
    case_map = {case["id"]: case for case in cases}
    base = base_url(config, env)
    records, failures = [], []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        for item in items:
            case = case_map.get(item.get("case_id"))
            if not case or case["vuln"] != "xss" or case["label"] != "malicious":
                failures.append(item.get("case_id", "unknown"))
                continue
            request = runner.wire_request(case)
            url = request_url(base, request)
            get_body = (urlencode([tuple(pair) for pair in request.get("form", [])]).encode("ascii")
                        if request["method"] == "GET" and request.get("form") else None)
            get_headers = request.get("headers", {})
            if get_body is not None and not any(key.lower() == "content-type" for key in get_headers):
                get_headers = {**get_headers, "Content-Type": "application/x-www-form-urlencoded"}
            result = check_page(browser, url, marker_for(request), get_body, get_headers)
            expected_status = result["http_status"]
            execution_status = ("blocked" if expected_status == 403 else
                                "executed" if result["executed"] else "not_executed")
            screenshot = output_dir / f"{item['case_id']}-{config}-pl{level}.png"
            result["page"].screenshot(path=str(screenshot), full_page=True)
            record = {
                "case_id": item["case_id"], "verification_mode": "waf_path",
                "configuration": config, "paranoia_level": level,
                "endpoint": request["path"],
                "test_timestamp": datetime.now(timezone.utc).isoformat(),
                "http_status": expected_status, "reflected": bool(item.get("reflected")),
                "executed": result["executed"], "execution_status": execution_status,
                "execution_signal": result["execution_signal"],
                "browser_error": result["browser_error"],
                "screenshot_path": screenshot.relative_to(ROOT).as_posix(),
                "commit_hash": runner.command(["git", "rev-parse", "HEAD"]).strip(),
                "corpus_sha256": corpus_digest(), "run_id": item["run_id"],
            }
            records.append(record)
            result["page"].close()
            if result["browser_error"]:
                failures.append(item["case_id"])
            print(f"{item['case_id']} {config} PL{level}: {execution_status} "
                  f"HTTP {expected_status}")
        browser.close()
    write_evidence(records, output_dir)
    if records:
        update_run_results(records, pending_file.parent)
    return failures


def update_run_results(records, run_dir):
    """Apply verified execution to row-level results and remove completed pending items."""
    result_path = run_dir / "results.json"
    pending_path = run_dir / "pending_browser_verification.json"
    rows = json.loads(result_path.read_text(encoding="utf-8"))
    pending = json.loads(pending_path.read_text(encoding="utf-8"))
    completed = set()
    for record in records:
        config = record["configuration"]
        key = (record["case_id"], config, record["paranoia_level"])
        completed.add(key)
        row = next((item for item in rows
                    if item["case_id"] == record["case_id"]
                    and item["paranoia_level"] == record["paranoia_level"]), None)
        if row is None:
            raise RuntimeError(f"No result row for browser evidence {key}")
        executed = record["execution_status"] == "executed"
        reflected = record["reflected"]
        if config == "ml_only":
            ml = row.setdefault("ml_enforcement", {})
            ml["execution_status"] = record["execution_status"]
            ml["reflected"] = reflected
            decision = ml.get("decision")
            bypass = runner.is_true_bypass_xss(
                row.get("label"), decision, False, reflected, record["execution_status"])
            ml["true_bypass_xss"] = bypass
            if decision == "allowed":
                ml["outcome"] = "true_bypass_xss" if bypass else "pass_without_effect"
                ml["true_bypass"] = bypass
            elif record["execution_status"] == "blocked":
                ml["outcome"] = "blocked"
                ml["true_bypass"] = False
        else:
            row["execution_status"] = record["execution_status"]
            row["reflected"] = reflected
            allowed = row.get("waf_decision") == "allowed"
            detected = row.get("detected") is True
            bypass = runner.is_true_bypass_xss(
                row.get("label"), row.get("waf_decision"), detected,
                reflected, record["execution_status"])
            row["true_bypass_xss"] = bypass
            row["true_bypass"] = bypass
            if allowed:
                row["outcome"] = ("true_bypass_xss" if bypass else
                                  "allowed_detected" if detected else "pass_without_effect")
            elif record["execution_status"] == "blocked":
                row["outcome"] = "blocked"
    result_path.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    pending = [item for item in pending
               if (item.get("case_id"), item.get("configuration"),
                   item.get("paranoia_level")) not in completed]
    pending_path.write_text(json.dumps(pending, indent=2, ensure_ascii=False), encoding="utf-8")
    refresh_summary(run_dir, rows)
    refresh_csv(run_dir, rows)


def refresh_csv(run_dir, rows):
    csv_path = run_dir / "results.csv"
    if not csv_path.is_file():
        return
    by_key = {(row["case_id"], row["paranoia_level"]): row for row in rows}
    with csv_path.open("r", newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        fields = reader.fieldnames
        csv_rows = list(reader)
    for item in csv_rows:
        result = by_key.get((item.get("case_id"), int(item.get("paranoia_level", 0))))
        if not result:
            continue
        for key in ("outcome", "true_bypass", "reflected", "execution_status", "true_bypass_xss"):
            if key in item:
                item[key] = result.get(key)
        ml = result.get("ml_enforcement") or {}
        for csv_key, result_key in (
            ("ml_outcome", "outcome"), ("ml_true_bypass", "true_bypass"),
            ("ml_execution_status", "execution_status"), ("ml_reflected", "reflected"),
            ("ml_true_bypass_xss", "true_bypass_xss"),
            ("ml_attack_score", "attack_score"), ("ml_threshold", "threshold"),
        ):
            if csv_key in item:
                item[csv_key] = ml.get(result_key)
    temp_path = csv_path.with_suffix(".csv.tmp")
    with temp_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(csv_rows)
    temp_path.replace(csv_path)


def refresh_summary(run_dir, rows):
    summary_path = run_dir / "summary.json"
    if not summary_path.is_file():
        return
    previous = json.loads(summary_path.read_text(encoding="utf-8"))
    by_level = []
    for old in previous.get("by_level", []):
        level = old["paranoia_level"]
        level_rows = [row for row in rows if row["paranoia_level"] == level]
        summary = {"paranoia_level": level, **runner.summarize(level_rows)}
        summary["by_technique"] = runner.summarize_by_technique(level_rows)
        summary["cases"] = [
            {"id": row["case_id"], "outcome": row["outcome"],
             "vuln": row.get("vuln", "sqli"), "family": row.get("family"),
             "waf_decision": row.get("waf_decision"), "detected": row.get("detected"),
             "reflected": row.get("reflected"),
             "execution_status": row.get("execution_status"),
             "true_bypass_xss": row.get("true_bypass_xss"),
             "semantic_effect": row.get("semantic_effect"),
             "http_status": row.get("http_status"),
             "ml_label": (row.get("ml") or {}).get("label"),
             "ml_score": (row.get("ml") or {}).get("score"),
             "ml_attack_score": (row.get("ml_enforcement") or {}).get("attack_score"),
             "ml_threshold": (row.get("ml_enforcement") or {}).get("threshold"),
             "ml_decision": (row.get("ml_enforcement") or {}).get("decision"),
             "ml_outcome": (row.get("ml_enforcement") or {}).get("outcome"),
             "ml_true_bypass": (row.get("ml_enforcement") or {}).get("true_bypass"),
             "rule_ids": row.get("rule_ids", []), "transport": row.get("transport")}
            for row in level_rows]
        by_level.append(summary)
    previous["by_level"] = by_level
    previous["by_technique"] = [summary["by_technique"] for summary in by_level]
    summary_path.write_text(json.dumps(previous, indent=2, ensure_ascii=False), encoding="utf-8")


def verify_waf_runtime(config, level, env):
    if config in ("crs_only", "hybrid"):
        actual_pl = runner.command(runner.COMPOSE + ["exec", "-T", "waf-crs",
                                                     "printenv", "BLOCKING_PARANOIA"], env).strip()
        if actual_pl != str(level):
            raise RuntimeError(f"Requested PL{level}, but running CRS uses PL{actual_pl}")
        backend = runner.command(runner.COMPOSE + ["exec", "-T", "waf-crs",
                                                   "printenv", "BACKEND"], env).strip()
        expected = "http://waf-ml:5001" if config == "hybrid" else "http://web-app:5000"
        if backend != expected:
            raise RuntimeError(f"{config} expects CRS BACKEND={expected}, found {backend!r}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--mode", required=True, choices=("app-control", "waf-path"))
    parser.add_argument("--config", choices=("crs_only", "ml_only", "hybrid"))
    parser.add_argument("--pl", type=int, choices=(1, 2, 3))
    parser.add_argument("--pending-file", type=Path)
    args = parser.parse_args()
    cases = runner.load_corpus(runner.DEFAULT_CORPUS)
    env = __import__("os").environ.copy()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if args.mode == "app-control":
        output_dir = ROOT / "results/raw/browser" / "app-control" / stamp
        failures = verify_app_control(cases, output_dir, env)
    else:
        if not args.config or not args.pl or not args.pending_file:
            parser.error("waf-path requires --config, --pl, and --pending-file")
        pending_file = args.pending_file.resolve()
        expected_parent = (ROOT / "results/raw/experiments").resolve()
        if pending_file.name != "pending_browser_verification.json" or pending_file.parent.parent != expected_parent:
            parser.error("--pending-file must be a run's results/raw/experiments/<run-id>/pending_browser_verification.json")
        verify_waf_runtime(args.config, args.pl, env)
        output_dir = ROOT / "results/raw/browser" / pending_file.parent.name / args.config / f"pl{args.pl}"
        failures = verify_waf_path(cases, pending_file, output_dir, env, args.config, args.pl)
    if failures:
        print("Verification failures: " + ", ".join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
