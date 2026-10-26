"""Offline regression checks for the corpus contract and request representation.

These checks model input selection from source. They do not execute SQL, contact
the fixture or assert that a payload bypasses a WAF.
"""
import base64
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import corpus


def request_case(method="GET", path="/search", *, params=None, form=None,
                 headers=None, raw_query=None, raw_body=None):
    """Minimal compiler input; full cases are exercised by CorpusTests below."""
    return {"request": {
        "method": method, "path": path,
        "params": params or [], "form": form or [], "headers": headers or {},
        "raw_query": raw_query, "raw_body": raw_body,
    }}


class RequestRepresentationTests(unittest.TestCase):
    def model(self, case):
        return corpus.parser_model(corpus.compile_request(case))

    def test_duplicate_query_values_keep_order_and_first_selection(self):
        case = request_case(params=[["q", "first value"], ["q", "second+value"]])
        compiled = corpus.compile_request(case)
        self.assertEqual(compiled["target"], "/search?q=first+value&q=second%2Bvalue")
        self.assertEqual(self.model(case)["query_pairs"],
                         [("q", "first value"), ("q", "second+value")])
        self.assertEqual(self.model(case)["selected"], {"q": "first value"})
        case["request"]["params"].reverse()
        self.assertEqual(self.model(case)["selected"], {"q": "second+value"})

    def test_duplicate_form_values_keep_order_and_first_selection(self):
        case = request_case("POST", "/login",
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                            form=[["username", "first"], ["username", "second"],
                                  ["password", "pw"]])
        self.assertEqual(corpus.compile_request(case)["body"],
                         b"username=first&username=second&password=pw")
        self.assertEqual(self.model(case)["selected"], {"username": "first", "password": "pw"})
        case["request"]["form"][:2] = list(reversed(case["request"]["form"][:2]))
        self.assertEqual(self.model(case)["selected"], {"username": "second", "password": "pw"})

    def test_raw_query_is_not_encoded_or_decoded_by_compiler(self):
        raw_query = "q=%2527%2520or%25201%253D1"
        case = request_case(raw_query=raw_query)
        self.assertEqual(corpus.compile_request(case)["target"], "/search?" + raw_query)
        # The application parser performs one decoding pass; %27 is still text.
        self.assertEqual(self.model(case)["selected"], {"q": "%27%20or%201%3D1"})

    def test_explicit_empty_raw_query_retains_the_query_delimiter(self):
        self.assertEqual(corpus.compile_request(request_case(raw_query=""))["target"], "/search?")
        self.assertEqual(corpus.compile_request(request_case())["target"], "/search")

    def test_raw_json_duplicate_keys_remain_exact_and_model_uses_last_value(self):
        raw_body = '{"username":"first","username":"cuối","password":"pw"}'
        case = request_case("POST", "/login", raw_body=raw_body,
                            headers={"Content-Type": "application/json; charset=utf-8"})
        self.assertEqual(corpus.compile_request(case)["body"], raw_body.encode("utf-8"))
        self.assertEqual(self.model(case)["selected"], {"username": "cuối", "password": "pw"})

    def test_json_body_is_ignored_after_content_type_changes_to_text_plain(self):
        case = request_case("POST", "/login", raw_body='{"username":"alice","password":"pw"}',
                            headers={"Content-Type": "application/json"})
        self.assertEqual(self.model(case)["selected"], {"username": "alice", "password": "pw"})
        original_body = corpus.compile_request(case)["body"]
        case["request"]["headers"]["Content-Type"] = "text/plain"
        self.assertEqual(corpus.compile_request(case)["body"], original_body)
        self.assertEqual(self.model(case)["selected"], {"username": "", "password": ""})

    def test_json_suffix_is_recognized_only_under_application_media_type(self):
        case = request_case("POST", "/login", raw_body='{"username":"alice"}',
                            headers={"Content-Type": "application/vendor+json"})
        self.assertEqual(self.model(case)["selected"]["username"], "alice")
        case["request"]["headers"]["Content-Type"] = "text/vendor+json"
        self.assertEqual(self.model(case)["selected"], {"username": "", "password": ""})

    def test_login_uses_form_and_ignores_query_parameters(self):
        case = request_case("POST", "/login",
                            params=[["username", "query-user"], ["password", "query-password"]],
                            form=[["username", "form-user"], ["password", "form-password"]],
                            headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(self.model(case)["selected"],
                         {"username": "form-user", "password": "form-password"})
        case["request"]["form"] = []
        self.assertEqual(self.model(case)["selected"], {"username": "", "password": ""})

    def test_missing_input_and_blank_input_have_distinct_selection(self):
        self.assertEqual(self.model(request_case())["selected"], {"q": "test"})
        self.assertEqual(self.model(request_case(params=[["q", ""]]))["selected"], {"q": ""})
        self.assertEqual(self.model(request_case(path="/product"))["selected"], {"id": "1"})

    def test_malformed_json_follows_silent_empty_input_branch(self):
        case = request_case("POST", "/login", raw_body='{"username":',
                            headers={"Content-Type": "application/json"})
        self.assertEqual(self.model(case)["selected"], {"username": "", "password": ""})

    def test_export_preserves_body_bytes_and_marks_results_unmeasured(self):
        # Only export metadata needs a complete case; use an explicit local input.
        case = request_case("POST", "/login", raw_body='{"username":"cuối"}',
                            headers={"Content-Type": "application/json"})
        case.update(schema_version="1.0", id="pd-001", technique="parsing-discrepancy", target="flask-mysql",
                    label="benign", role="benign-control", baseline_id=None,
                    control_ids=[], expected_app={}, note="Source expectation only.")
        exported = corpus.export_case(case)
        body = base64.b64decode(exported["request"]["body_base64"], validate=True)
        self.assertEqual(body, corpus.compile_request(case)["body"])
        self.assertEqual(exported["request"]["body_length"], len(body))
        self.assertEqual(exported["measurement_status"], "not-run")
        self.assertEqual(exported["schema_version"], "1.0")
        self.assertEqual(exported["representation"], "compiled-http-request-v1")


class CorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = corpus.load_corpus()
        cls.index = {case["id"]: case for case in cls.cases}
        cls.schema = corpus.read_json(corpus.CORPUS_ROOT / "schema.json")

    def case_for(self, role):
        return deepcopy(next(case for case in self.cases if case["role"] == role))

    def test_corpus_covers_all_techniques_and_research_roles(self):
        self.assertEqual({case["technique"] for case in self.cases}, set(corpus.TECHNIQUES))
        for technique in corpus.TECHNIQUES:
            with self.subTest(technique=technique):
                group = [case for case in self.cases if case["technique"] == technique]
                self.assertEqual({case["role"] for case in group}, set(corpus.ROLES))

    def test_published_schema_and_validator_share_structural_contract(self):
        # This checks drift in the published contract; it is not a JSON Schema engine.
        definitions = self.schema["$defs"]
        for name, expected_fields in (("case", corpus.CASE_FIELDS),
                                      ("request", corpus.REQUEST_FIELDS),
                                      ("expectation", corpus.EXPECTATION_FIELDS)):
            with self.subTest(definition=name):
                definition = definitions[name]
                self.assertEqual(set(definition["required"]), expected_fields)
                self.assertEqual(set(definition["properties"]), expected_fields)
                self.assertIs(definition["additionalProperties"], False)
        properties = definitions["case"]["properties"]
        self.assertEqual(set(properties["technique"]["enum"]), set(corpus.TECHNIQUES))
        self.assertEqual(set(properties["role"]["enum"]), set(corpus.ROLES))
        self.assertEqual(properties["schema_version"]["const"], "1.0")
        self.assertEqual(properties["target"]["const"], "flask-mysql")
        self.assertEqual(definitions["pairs"]["items"]["minItems"], 2)
        self.assertEqual(definitions["pairs"]["items"]["maxItems"], 2)
        for case in self.cases:
            self.assertEqual(set(case), set(definitions["case"]["required"]))
            self.assertEqual(set(case["request"]), set(definitions["request"]["required"]))
            self.assertEqual(set(case["expected_app"]), set(definitions["expectation"]["required"]))

    def test_corpus_expected_selected_values_match_parser_model(self):
        for case in self.cases:
            with self.subTest(case_id=case["id"]):
                prediction = corpus.parser_model(corpus.compile_request(case))
                self.assertEqual(prediction["selected"], case["expected_app"]["selected"])

    def test_experiment_plans_reference_the_matching_corpus_and_levels(self):
        plans = corpus.load_plans(self.cases)
        self.assertEqual({plan["technique"] for plan in plans}, set(corpus.TECHNIQUES))
        for plan in plans:
            self.assertEqual(plan["paranoia_levels"], [1, 2, 3])
            self.assertEqual(plan["corpus"], f"dataset/bypass/{plan['technique']}/cases.json")
            self.assertEqual(plan["measurement_status"], "not-run")

    def test_plan_cannot_point_to_another_technique_or_claim_measurements(self):
        original = corpus.load_plans(self.cases)[0]
        for field, value, message in (("corpus", "dataset/bypass/case-comment/cases.json", "wrong corpus"),
                                      ("measurement_status", "complete", "not measured evidence")):
            with self.subTest(field=field):
                plan = deepcopy(original)
                plan[field] = value
                with patch.object(corpus, "read_json", return_value=plan):
                    with self.assertRaisesRegex(corpus.CorpusError, message):
                        corpus.load_plans(self.cases)

    def test_raw_and_structured_query_or_body_cannot_be_combined(self):
        for raw_field, pair_field, raw in (("raw_query", "params", "q=raw"),
                                          ("raw_body", "form", "username=raw")):
            with self.subTest(raw_field=raw_field):
                case = self.case_for("baseline")
                case["request"][raw_field] = raw
                case["request"][pair_field] = [["q", "structured"]]
                with self.assertRaisesRegex(corpus.CorpusError, "mutually exclusive"):
                    corpus.validate_case(case)

    def test_duplicate_json_definition_fields_are_rejected_even_when_nested(self):
        with self.assertRaisesRegex(corpus.CorpusError, "Duplicate JSON field"):
            corpus.unique_object([("id", "one"), ("id", "two")])
        with patch.object(Path, "read_text", return_value='[{"request":{"path":"/search","path":"/login"}}]'):
            with self.assertRaisesRegex(corpus.CorpusError, "Duplicate JSON field"):
                corpus.read_json("unused.json")

    def test_duplicate_case_ids_are_rejected(self):
        with self.assertRaisesRegex(corpus.CorpusError, "Duplicate case ID"):
            corpus.validate_cases(deepcopy(self.cases) + [deepcopy(self.cases[0])])

    def test_broken_baseline_link_is_rejected(self):
        cases = deepcopy(self.cases)
        mutation = next(case for case in cases if case["role"] == "mutation")
        mutation["baseline_id"] = "not-a-case"
        with self.assertRaisesRegex(corpus.CorpusError, "missing baseline"):
            corpus.validate_cases(cases)

    def test_baseline_from_another_technique_is_rejected(self):
        cases = deepcopy(self.cases)
        mutation = next(case for case in cases if case["role"] == "mutation")
        other = next(case for case in cases
                     if case["role"] == "baseline" and case["technique"] != mutation["technique"])
        mutation["baseline_id"] = other["id"]
        with self.assertRaisesRegex(corpus.CorpusError, "incompatible baseline"):
            corpus.validate_cases(cases)

    def test_broken_control_link_is_rejected(self):
        cases = deepcopy(self.cases)
        mutation = next(case for case in cases if case["role"] == "mutation")
        mutation["control_ids"] = ["not-a-case"]
        with self.assertRaisesRegex(corpus.CorpusError, "missing control"):
            corpus.validate_cases(cases)

    def test_mutations_require_both_benign_and_negative_controls(self):
        for retained_role in ("benign-control", "negative-control"):
            with self.subTest(retained_role=retained_role):
                cases = deepcopy(self.cases)
                mutation = next(case for case in cases if case["role"] == "mutation")
                mutation["control_ids"] = [cid for cid in mutation["control_ids"]
                                           if self.index[cid]["role"] == retained_role]
                with self.assertRaisesRegex(corpus.CorpusError, "both benign and negative controls"):
                    corpus.validate_cases(cases)

    def test_incorrect_selected_value_is_rejected(self):
        case = self.case_for("baseline")
        key = next(iter(case["expected_app"]["selected"]))
        case["expected_app"]["selected"][key] += " unexpected"
        with self.assertRaisesRegex(corpus.CorpusError, "selected values differ"):
            corpus.validate_case(case)

    def test_negative_control_cannot_claim_semantic_effect(self):
        case = self.case_for("negative-control")
        case["expected_app"]["semantic_effect"] = True
        case["expected_app"]["sql_error"] = False
        with self.assertRaisesRegex(corpus.CorpusError, "negative control must have no expected effect"):
            corpus.validate_case(case)

    def test_malformed_raw_percent_escapes_are_rejected(self):
        case = self.case_for("baseline")
        case["request"]["params"] = []
        case["request"]["raw_query"] = "q=%2Z"
        with self.assertRaisesRegex(corpus.CorpusError, "malformed percent escape"):
            corpus.validate_case(case)

    def test_transport_headers_and_case_insensitive_duplicates_are_rejected(self):
        for headers, message in (({"Host": "example.invalid"}, "owned by the transport"),
                                 ({"Content-Type": "text/plain", "content-type": "text/plain"},
                                  "duplicate case-insensitive header")):
            with self.subTest(headers=headers):
                case = self.case_for("baseline")
                case["request"]["headers"] = headers
                with self.assertRaisesRegex(corpus.CorpusError, message):
                    corpus.validate_case(case)

    def test_unknown_definition_fields_are_rejected(self):
        case = self.case_for("baseline")
        case["unexpected"] = "value"
        with self.assertRaisesRegex(corpus.CorpusError, "extra="):
            corpus.validate_case(case)

    def test_validate_cli_reports_source_checks_and_no_live_measurement(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(corpus.main(["validate"]), 0)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["cases"], len(self.cases))
        self.assertEqual(set(report["techniques"]), set(corpus.TECHNIQUES))
        self.assertEqual(report["live_waf_mysql"], "not-run")

    def test_cli_empty_filter_returns_failure_with_explanation(self):
        stderr = io.StringIO()
        stdout = io.StringIO()
        with redirect_stderr(stderr), redirect_stdout(stdout):
            self.assertEqual(corpus.main(["export", "--case", "no-such-case"]), 1)
        self.assertIn("No cases match", stderr.getvalue())
        self.assertEqual(stdout.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
