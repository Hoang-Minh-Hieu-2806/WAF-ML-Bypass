#!/usr/bin/env python3
"""Validate the mixed v1 SQLi and v2 XSS research corpus using stdlib only."""

import json
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent
TECHNIQUES = {"hpp", "double-encoding", "case-comment", "parsing-discrepancy"}
V1_PATHS = {"/search", "/product", "/login"}
V2_PATHS = V1_PATHS | {"/comment", "/comment-escaped"}
LABELS = {"benign", "malicious"}
APP_EFFECTS = {"executed", "not_executed", "none"}
WAF_OUTCOMES = {"blocked", "allowed"}
XSS_FAMILIES = {
    "xss.tag", "xss.event", "xss.encoding", "xss.case-comment",
    "xss.hpp", "benign.html", "benign.lt",
}
BENIGN_FAMILIES = {"xss.encoding", "benign.html", "benign.lt"}


class CorpusError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise CorpusError(message)


def validate_pairs(value, where):
    require(isinstance(value, list), f"{where}: expected ordered list of pairs")
    for index, pair in enumerate(value):
        require(isinstance(pair, list) and len(pair) == 2,
                f"{where}[{index}]: expected [key, value]")
        require(all(isinstance(part, str) for part in pair),
                f"{where}[{index}]: key and value must be strings")


def validate_v1(case, where):
    # Historical v1 files omit empty params/form lists; omission means no pairs.
    required = {"id", "technique", "label", "method", "path", "expected_app"}
    require(required <= case.keys(), f"{where}: missing v1 keys {sorted(required - case.keys())}")
    require(case["method"] in {"GET", "POST"}, f"{where}: invalid method")
    require(case["path"] in V1_PATHS, f"{where}: v1 path must target an existing SQLi endpoint")
    require(case["expected_app"] in {"executed", "blocked"}, f"{where}: invalid v1 expected_app")
    require("control" not in case or case["control"] == "none",
            f"{where}: unsupported v1 control value")
    params = case.get("params", [])
    form = case.get("form", [])
    validate_pairs(params, f"{where}.params")
    validate_pairs(form, f"{where}.form")
    if case["method"] == "GET":
        require(not form or case["path"] == "/search",
                f"{where}: unexpected GET body fixture")


def validate_v2(case, where):
    required = {
        "id", "vuln", "technique", "family", "label", "request",
        "expected_waf_outcome", "expected_app_effect", "control", "note",
    }
    require(required <= case.keys(), f"{where}: missing v2 keys {sorted(required - case.keys())}")
    require(case["vuln"] == "xss", f"{where}: v2 cases in this corpus must declare vuln=xss")
    require(case["family"] in XSS_FAMILIES, f"{where}: unknown XSS family {case['family']!r}")
    require(case["label"] in LABELS, f"{where}: invalid label")
    require(case["expected_waf_outcome"] in WAF_OUTCOMES, f"{where}: invalid WAF expectation")
    require(case["expected_app_effect"] in APP_EFFECTS, f"{where}: invalid app-effect expectation")
    require(case["label"] != "benign" or case["expected_app_effect"] == "none",
            f"{where}: benign cases must have expected_app_effect=none")
    require(case["label"] != "benign" or case["family"] in BENIGN_FAMILIES,
            f"{where}: benign case must use an encoding or benign.* family")
    require(case["label"] != "malicious" or case["family"].startswith("xss."),
            f"{where}: malicious case must use an xss.* family")
    request = case["request"]
    require(isinstance(request, dict), f"{where}.request: expected object")
    required_request = {"method", "path", "params", "form", "headers", "transport"}
    require(required_request <= request.keys(),
            f"{where}.request: missing keys {sorted(required_request - request.keys())}")
    require(request["method"] in {"GET", "POST"}, f"{where}: invalid method")
    require(request["path"] in V2_PATHS, f"{where}: invalid request path")
    require(request["path"] == "/comment", f"{where}: XSS cases must target /comment")
    require(request["transport"] in {None, "chunked"}, f"{where}: invalid transport")
    require(isinstance(request["headers"], dict), f"{where}.request.headers: expected object")
    validate_pairs(request["params"], f"{where}.request.params")
    validate_pairs(request["form"], f"{where}.request.form")
    control = case["control"]
    if control is not None:
        require(isinstance(control, dict), f"{where}.control: expected object or null")
        require(control.get("endpoint") == "/comment-escaped",
                f"{where}.control.endpoint must be /comment-escaped")
        require(set(control.get("must_not", [])) == {"reflect", "execute"},
                f"{where}.control.must_not must include reflect and execute")
    require(isinstance(case["note"], str) and case["note"].strip(), f"{where}: note must be non-empty")


def main():
    ids = set()
    labels = Counter()
    by_technique = Counter()
    by_family = Counter()
    versions = Counter()
    errors = []

    for technique in sorted(TECHNIQUES):
        path = ROOT / technique / "cases.json"
        if not path.is_file():
            errors.append(f"missing corpus file: {path.relative_to(ROOT)}")
            continue
        try:
            cases = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{path.relative_to(ROOT)}: {exc}")
            continue
        if not isinstance(cases, list):
            errors.append(f"{path.relative_to(ROOT)}: top-level JSON must be an array")
            continue
        for index, case in enumerate(cases):
            where = f"{technique}/cases.json[{index}]"
            if not isinstance(case, dict):
                errors.append(f"{where}: case must be an object")
                continue
            try:
                require(case.get("technique") == technique,
                        f"{where}: technique must match containing directory")
                case_id = case.get("id")
                require(isinstance(case_id, str) and case_id.strip(), f"{where}: missing id")
                require(case_id not in ids, f"{where}: duplicate corpus id {case_id!r}")
                if case_id:
                    ids.add(case_id)
                require(case.get("label") in LABELS, f"{where}: invalid label")
                if "request" in case:
                    validate_v2(case, where)
                    versions["v2"] += 1
                    by_family[case["family"]] += 1
                else:
                    validate_v1(case, where)
                    versions["v1"] += 1
                labels[case["label"]] += 1
                by_technique[technique] += 1
            except CorpusError as exc:
                errors.append(str(exc))

    if versions["v1"] != 26:
        errors.append(f"expected 26 legacy v1 cases, found {versions['v1']}")
    if versions["v2"] != 10:
        errors.append(f"expected 10 XSS v2 cases, found {versions['v2']}")
    xss_labels = Counter()
    for technique in TECHNIQUES:
        cases_path = ROOT / technique / "cases.json"
        if not cases_path.is_file():
            continue
        try:
            for case in json.loads(cases_path.read_text(encoding="utf-8")):
                if isinstance(case, dict) and case.get("vuln") == "xss":
                    xss_labels[case.get("label")] += 1
        except (OSError, json.JSONDecodeError):
            pass
    if xss_labels["benign"] != 4 or xss_labels["malicious"] != 6:
        errors.append(f"expected XSS split 4 benign / 6 malicious, found {dict(xss_labels)}")

    if errors:
        print("Corpus validation FAILED:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"Corpus validation passed: {len(ids)} unique cases ({versions['v1']} v1 SQLi, "
          f"{versions['v2']} v2 XSS; XSS 4 benign / 6 malicious).")
    print("By technique: " + ", ".join(f"{key}={by_technique[key]}" for key in sorted(by_technique)))
    print("XSS families: " + ", ".join(f"{key}={by_family[key]}" for key in sorted(by_family)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
