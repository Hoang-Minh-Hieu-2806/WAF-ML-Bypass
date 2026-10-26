"""Validate and compile Long's payload corpus without sending HTTP requests.

Standard library only. Parser checks model the branches in web-app/app.py;
they are not Flask/MySQL integration tests or observations of CRS behaviour.
"""
import argparse
import base64
from collections import Counter
import json
from pathlib import Path
import re
import sys
from urllib.parse import parse_qsl, urlencode


ROOT = Path(__file__).resolve().parents[1]
CORPUS_ROOT = ROOT / "dataset" / "bypass"
TECHNIQUES = ("hpp", "double-encoding", "case-comment", "parsing-discrepancy")
PREFIXES = dict(zip(TECHNIQUES, ("hpp", "de", "cc", "pd")))
ROLES = ("baseline", "mutation", "benign-control", "negative-control")
CASE_FIELDS = {"schema_version", "id", "technique", "title", "target", "label", "role",
               "baseline_id", "control_ids", "request", "expected_app", "note"}
REQUEST_FIELDS = {"method", "path", "params", "form", "headers", "raw_query", "raw_body"}
EXPECTATION_FIELDS = {"selected", "semantic_effect", "sql_error", "http_status"}
PLAN_FIELDS = {"schema_version", "technique", "target", "corpus", "paranoia_levels",
               "comparison_unit", "measurement_status"}
RESERVED_HEADERS = {"host", "content-length", "transfer-encoding", "connection",
                    "x-lab-case-id"}


class CorpusError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise CorpusError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON field in corpus definition: {key!r}")
        result[key] = value
    return result


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CorpusError(f"Cannot read {path}: {error}") from error


def fields(value, expected, context):
    require(isinstance(value, dict), f"{context}: expected an object")
    require(set(value) == expected,
            f"{context}: missing={sorted(expected - set(value))}, extra={sorted(set(value) - expected)}")


def string_pairs(value, context):
    require(isinstance(value, list), f"{context}: expected an ordered list of pairs")
    require(all(isinstance(pair, list) and len(pair) == 2
                and all(isinstance(item, str) for item in pair) for pair in value),
            f"{context}: every pair must contain exactly two strings")


def content_type(headers):
    return next((value.split(";", 1)[0].strip().lower()
                 for key, value in headers.items() if key.lower() == "content-type"), "")


def compile_request(case):
    """Return a relative target and exact UTF-8 body bytes; never decode raw fields."""
    request = case["request"]
    query = request["raw_query"]
    if query is None:
        query = urlencode([tuple(pair) for pair in request["params"]], encoding="utf-8", errors="strict")
    has_query = request["raw_query"] is not None or bool(request["params"])
    target = request["path"] + ("?" + query if has_query else "")
    headers = dict(request["headers"])
    if request["raw_body"] is not None:
        body = request["raw_body"].encode("utf-8")
    elif request["form"]:
        body = urlencode([tuple(pair) for pair in request["form"]], encoding="utf-8", errors="strict").encode("ascii")
    else:
        body = b""
    return {"method": request["method"], "target": target, "headers": headers, "body": body}


def first_values(pairs):
    result = {}
    for key, value in pairs:
        result.setdefault(key, value)
    return result


def parser_model(compiled):
    """Predict selected values from source; deliberately does not execute any SQL."""
    path, _, query = compiled["target"].partition("?")
    query_pairs = parse_qsl(query, keep_blank_values=True, encoding="utf-8", errors="strict")
    media_type = content_type(compiled["headers"])
    body = compiled["body"].decode("utf-8")
    form_pairs = (parse_qsl(body, keep_blank_values=True, encoding="utf-8", errors="strict")
                  if media_type == "application/x-www-form-urlencoded" else [])
    parsed_json = None
    if media_type == "application/json" or (media_type.startswith("application/") and media_type.endswith("+json")):
        try:
            # JSON body duplicates are intentional test data; corpus fields are not.
            parsed_json = json.loads(body)
        except json.JSONDecodeError:
            pass  # Flask get_json(silent=True) falls back to form in this fixture.
    if path == "/search":
        selected = {"q": first_values(query_pairs).get("q", "test")}
    elif path == "/product":
        selected = {"id": first_values(query_pairs).get("id", "1")}
    else:
        data = parsed_json or first_values(form_pairs)
        require(isinstance(data, dict), "JSON login input must be an object for this corpus")
        selected = {"username": data.get("username", ""), "password": data.get("password", "")}
    return {"query_pairs": query_pairs, "form_pairs": form_pairs,
            "json_object": parsed_json, "selected": selected}


def validate_case(case):
    fields(case, CASE_FIELDS, "case")
    cid = case["id"]
    require(isinstance(cid, str), "case.id: expected a string")
    technique = case["technique"]
    require(technique in TECHNIQUES, f"{cid}: unsupported technique")
    require(re.fullmatch(PREFIXES[technique] + r"-[0-9]{3}", cid) is not None,
            f"{cid}: ID must match its technique prefix")
    require(case["schema_version"] == "1.0", f"{cid}: unsupported schema version")
    require(case["target"] == "flask-mysql", f"{cid}: unsupported backend")
    for name in ("title", "note"):
        require(isinstance(case[name], str) and case[name].strip(), f"{cid}.{name}: empty text")
    require(case["label"] in ("benign", "malicious"), f"{cid}: invalid intent label")
    require(case["role"] in ROLES, f"{cid}: invalid role")
    require(case["baseline_id"] is None or isinstance(case["baseline_id"], str),
            f"{cid}: invalid baseline_id")
    controls = case["control_ids"]
    require(isinstance(controls, list) and all(isinstance(item, str) for item in controls),
            f"{cid}: control_ids must be a list of strings")
    require(len(set(controls)) == len(controls), f"{cid}: duplicate control IDs")
    require(cid not in controls, f"{cid}: self-referencing control")
    request = case["request"]
    fields(request, REQUEST_FIELDS, f"{cid}.request")
    route = (request["method"], request["path"])
    require(route in (("GET", "/search"), ("GET", "/product"), ("POST", "/login")),
            f"{cid}: method/path is not a fixture route")
    for name in ("params", "form"):
        string_pairs(request[name], f"{cid}.{name}")
    for raw, pairs in (("raw_query", "params"), ("raw_body", "form")):
        require(request[raw] is None or isinstance(request[raw], str), f"{cid}.{raw}: expected string/null")
        require(request[raw] is None or not request[pairs], f"{cid}: {raw} and {pairs} are mutually exclusive")
    query = request["raw_query"]
    if query is not None:
        require(all(32 < ord(char) < 127 and char != "#" for char in query),
                f"{cid}: raw_query must be ASCII without whitespace or fragments")
        require(re.search(r"%(?![0-9A-Fa-f]{2})", query) is None, f"{cid}: malformed percent escape")
    headers = request["headers"]
    require(isinstance(headers, dict), f"{cid}.headers: expected an object")
    lowered = set()
    for key, value in headers.items():
        require(isinstance(key, str) and re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key),
                f"{cid}: invalid header name")
        require(isinstance(value, str) and all(32 <= ord(char) < 127 for char in value),
                f"{cid}: header values must be printable ASCII")
        require(key.lower() not in lowered, f"{cid}: duplicate case-insensitive header")
        require(key.lower() not in RESERVED_HEADERS, f"{cid}: header {key} is owned by the transport")
        lowered.add(key.lower())
    if request["form"]:
        require(content_type(headers) == "application/x-www-form-urlencoded",
                f"{cid}: form pairs require the form Content-Type")
    expected = case["expected_app"]
    fields(expected, EXPECTATION_FIELDS, f"{cid}.expected_app")
    require(isinstance(expected["selected"], dict)
            and all(isinstance(k, str) and isinstance(v, str) for k, v in expected["selected"].items()),
            f"{cid}: selected must map string keys to string values")
    for name in ("semantic_effect", "sql_error"):
        require(expected[name] is None or type(expected[name]) is bool,
                f"{cid}.{name}: expected boolean/null")
    require(type(expected["http_status"]) is int and expected["http_status"] == 200,
            f"{cid}: this corpus expects the fixture's HTTP 200 response contract")
    require(not (expected["sql_error"] and expected["semantic_effect"]),
            f"{cid}: SQL error cannot prove a semantic effect")
    if case["role"] == "baseline":
        require(case["baseline_id"] is None and case["label"] == "malicious"
                and expected["semantic_effect"] is True and expected["sql_error"] is False,
                f"{cid}: baseline must be an effective malicious source expectation")
    elif case["role"] == "benign-control":
        require(case["baseline_id"] is None and case["label"] == "benign"
                and expected["semantic_effect"] is False and expected["sql_error"] is False,
                f"{cid}: invalid benign control expectation")
    else:
        require(isinstance(case["baseline_id"], str), f"{cid}: baseline link is required")
    if case["role"] == "mutation":
        require(case["label"] == "malicious", f"{cid}: mutation intent must be malicious")
    if case["role"] == "negative-control":
        require(expected["semantic_effect"] is False, f"{cid}: negative control must have no expected effect")
    try:
        predicted = parser_model(compile_request(case))["selected"]
    except (UnicodeError, ValueError) as error:
        raise CorpusError(f"{cid}: cannot compile/model request: {error}") from error
    require(predicted == expected["selected"],
            f"{cid}: selected values differ: model={predicted!r}, expected={expected['selected']!r}")


def validate_cases(cases):
    require(isinstance(cases, list) and cases, "Corpus must be a nonempty array")
    index = {}
    for case in cases:
        validate_case(case)
        require(case["id"] not in index, f"Duplicate case ID: {case['id']}")
        index[case["id"]] = case
    for case in cases:
        cid = case["id"]
        baseline = case["baseline_id"]
        if baseline is not None:
            require(baseline in index, f"{cid}: missing baseline {baseline}")
            reference = index[baseline]
            require(reference["role"] == "baseline" and reference["technique"] == case["technique"]
                    and reference["target"] == case["target"], f"{cid}: incompatible baseline")
            require(reference["request"]["path"] == case["request"]["path"],
                    f"{cid}: baseline must use the same endpoint")
        roles = set()
        for control in case["control_ids"]:
            require(control in index, f"{cid}: missing control {control}")
            reference = index[control]
            require(reference["role"] in ("benign-control", "negative-control")
                    and reference["technique"] == case["technique"]
                    and reference["request"]["path"] == case["request"]["path"],
                    f"{cid}: incompatible control {control}")
            roles.add(reference["role"])
        if case["role"] == "mutation":
            require({"benign-control", "negative-control"} <= roles,
                    f"{cid}: mutation needs both benign and negative controls")
    return cases


def load_corpus(root=CORPUS_ROOT):
    cases = []
    for technique in TECHNIQUES:
        path = Path(root) / technique / "cases.json"
        group = read_json(path)
        require(isinstance(group, list) and group, f"{path}: expected a nonempty case array")
        for case in group:
            require(isinstance(case, dict) and case.get("technique") == technique,
                    f"{path}: case technique does not match its directory")
        cases.extend(group)
    validate_cases(cases)
    for technique in TECHNIQUES:
        roles = {case["role"] for case in cases if case["technique"] == technique}
        require(set(ROLES) <= roles, f"{technique}: missing baseline/mutation/controls")
    return cases


def export_case(case):
    compiled = compile_request(case)
    return {"schema_version": case["schema_version"], "representation": "compiled-http-request-v1",
            "id": case["id"], "technique": case["technique"], "target": case["target"],
            "label": case["label"], "role": case["role"], "baseline_id": case["baseline_id"],
            "control_ids": case["control_ids"],
            "request": {"method": compiled["method"], "target": compiled["target"],
                        "headers": compiled["headers"],
                        "body_base64": base64.b64encode(compiled["body"]).decode("ascii"),
                        "body_length": len(compiled["body"])},
            "expected_app": case["expected_app"],
            "measurement_status": "not-run", "note": case["note"]}


def load_plans(cases, root=ROOT / "experiments"):
    plans = []
    techniques = {case["technique"] for case in cases}
    for technique in TECHNIQUES:
        plan = read_json(Path(root) / technique / "plan.json")
        fields(plan, PLAN_FIELDS, f"{technique}.plan")
        require(plan["schema_version"] == "1.0" and plan["technique"] == technique
                and plan["target"] == "flask-mysql", f"{technique}: incompatible experiment plan")
        require(plan["corpus"] == f"dataset/bypass/{technique}/cases.json"
                and technique in techniques, f"{technique}: plan points to the wrong corpus")
        require(plan["paranoia_levels"] == [1, 2, 3]
                and all(type(level) is int for level in plan["paranoia_levels"]),
                f"{technique}: plan must compare PL1/2/3")
        require(isinstance(plan["comparison_unit"], str) and plan["comparison_unit"].strip(),
                f"{technique}: empty comparison unit")
        require(plan["measurement_status"] == "not-run", f"{technique}: a plan is not measured evidence")
        plans.append(plan)
    return plans


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("validate", "preview", "export"))
    parser.add_argument("--technique", choices=TECHNIQUES)
    parser.add_argument("--case", dest="case_id")
    args = parser.parse_args(argv)
    try:
        all_cases = load_corpus()
        load_plans(all_cases)
        selected = [case for case in all_cases
                    if (args.technique is None or case["technique"] == args.technique)
                    and (args.case_id is None or case["id"] == args.case_id)]
        require(selected, "No cases match the requested filters")
        if args.action == "validate":
            report = {"cases": len(selected), "techniques": dict(Counter(c["technique"] for c in selected)),
                      "roles": dict(Counter(c["role"] for c in selected)),
                      "checks": ["structure", "unique IDs", "baseline/control links", "source parser model", "experiment plans"],
                      "live_waf_mysql": "not-run"}
            print(json.dumps(report, indent=2, ensure_ascii=False))
        elif args.action == "export":
            print(json.dumps([export_case(case) for case in selected], indent=2, ensure_ascii=False))
        else:
            previews = []
            for case in selected:
                preview = export_case(case)
                preview["parser_model"] = parser_model(compile_request(case))
                previews.append(preview)
            print(json.dumps(previews, indent=2, ensure_ascii=False))
    except (CorpusError, TypeError, UnicodeError) as error:
        print(f"Corpus validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
