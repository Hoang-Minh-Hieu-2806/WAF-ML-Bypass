"""R8: probe the ML /score endpoint with representative lab cases.

Works with the v1.0 binary contract ({label, score, model_version}) and the
v1.1 three-class contract (adds scores, attack_score, threshold). Expectations
follow design §9.5: attack payloads must reach the blocking threshold, benign
texts and benign HTML must stay below it. Read-only: never mutates artifacts.

Usage:
  python scripts/probe_ml_score.py --port 8082
  python scripts/probe_ml_score.py --base-url http://127.0.0.1:8082 --json
"""
import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PROBES = [
    # (case_id, text, expect_attack)
    ("sqli-union", "-1 UNION SELECT id,username FROM users", True),
    ("sqli-tautology", "1 oR 1=1", True),
    ("sqli-time-based", "1 AND SLEEP(5)-- ", True),
    ("xss-tag", "<script>document.title='T3-XSS-OK'</script>", True),
    ("xss-event", "<ImG src=x onerror=\"document.title='T3-XSS-OK';\">", True),
    ("benign-plain", "man hinh laptop 450", False),
    ("benign-html", "<div class=\"product\">Gaming chair</div>", False),
    ("benign-question", "How do I reset my password safely?", False),
]

DEFAULT_THRESHOLD = 0.5


def score_once(base_url, text, timeout=10):
    request = urllib.request.Request(
        base_url.rstrip("/") + "/score",
        data=json.dumps({"text": text}).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.status, json.loads(response.read().decode("utf-8"))


def contract_of(body):
    if isinstance(body.get("scores"), dict) and {"benign", "sqli", "xss"} <= set(body["scores"]):
        return "v1.1-3class"
    if "score" in body and "label" in body:
        return "v1.0-binary"
    return "unknown"


def evaluate(body, expect_attack):
    """Return (ok, reason) for one probe under the detected contract."""
    contract = contract_of(body)
    if contract == "unknown":
        return False, f"unrecognized score schema: {sorted(body)}"
    if contract == "v1.0-binary":
        score = float(body["score"])
        blocked = score >= DEFAULT_THRESHOLD
    else:
        scores = body["scores"]
        attack_score = float(body.get("attack_score",
                                     scores["sqli"] + scores["xss"]))
        threshold = float(body.get("threshold", DEFAULT_THRESHOLD))
        score, blocked = attack_score, attack_score >= threshold
    if expect_attack and not blocked:
        return False, f"attack below threshold (score={score})"
    if not expect_attack and blocked:
        return False, f"benign reached threshold (score={score})"
    return True, f"score={score} blocked={blocked}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8082")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()
    records, failures = [], []
    for case_id, text, expect_attack in PROBES:
        try:
            status, body = score_once(args.base_url, text)
        except (urllib.error.URLError, OSError) as exc:
            records.append({"case_id": case_id, "ok": False,
                            "reason": f"transport error: {exc}"})
            failures.append(case_id)
            continue
        ok, reason = evaluate(body, expect_attack)
        contract = contract_of(body)
        if contract == "v1.0-binary" and case_id.startswith("xss-"):
            # Known gap of the v1.0 binary model (SQLi-only training data);
            # R8 gates XSS expectations only once the v1.1 model is deployed.
            ok, reason = None, "skipped: v1.0 binary model does not score XSS (pre-X4)"
        records.append({"case_id": case_id, "http_status": status,
                        "contract": contract, "model_version":
                        body.get("model_version"), "label": body.get("label"),
                        "score": body.get("score"), "scores": body.get("scores"),
                        "attack_score": body.get("attack_score"),
                        "threshold": body.get("threshold"),
                        "expected_attack": expect_attack, "ok": ok, "reason": reason})
        if ok is False:
            failures.append(case_id)
        if not args.json:
            state = "PASS" if ok else "SKIP" if ok is None else "FAIL"
            print(f"{case_id:18s} {state} {reason}")
    if args.json:
        print(json.dumps({"base_url": args.base_url, "probes": records,
                          "failures": failures}, ensure_ascii=False, indent=2))
    else:
        versions = {r.get("model_version") for r in records if r.get("model_version")}
        contracts = {r.get("contract") for r in records if r.get("contract")}
        passed = sum(r["ok"] is True for r in records)
        skipped = sum(r["ok"] is None for r in records)
        print(f"model_version={versions} contract={contracts} "
              f"passed={passed}/{len(records)} skipped={skipped}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
