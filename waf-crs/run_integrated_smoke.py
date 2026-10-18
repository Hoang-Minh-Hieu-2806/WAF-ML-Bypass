"""Verify CRS blocking and application evidence on the Flask/MySQL stack.

Build with `docker compose up -d --build --wait` first. This runner changes
only CRS_PL in the integrated Compose stack; the SQLite lab is independent.
"""
import argparse
import csv
import hashlib
import json
import os
import platform
import time
import uuid
from datetime import datetime, timezone

from run_baseline import ROOT, audit_id, command, lines_since, send, summarize

COMPOSE = ["docker", "compose", "-f", str(ROOT / "docker-compose.yml")]
AUDIT = ROOT / "logs/waf/integrated/audit.log"
APP = ROOT / "logs/application/integrated/app.jsonl"


def loopback_port(service, port, env):
    binding = command(COMPOSE + ["port", service, str(port)], env).strip()
    if not binding.startswith("127.0.0.1:"):
        raise RuntimeError(f"Expected a loopback binding for {service}, got {binding!r}")
    return int(binding.rsplit(":", 1)[1])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--levels", nargs="+", type=int, choices=[1, 2, 3], default=[1])
    args = parser.parse_args()
    corpus_path = ROOT / "waf-crs/integrated-smoke.json"
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    out = ROOT / "results/raw/crs-integrated" / run_id
    out.mkdir(parents=True)
    env = os.environ.copy()
    metadata = {
        "run_id": run_id, "stack": "Flask/PyMySQL/MySQL", "levels": args.levels,
        "host": platform.platform(), "python_runner": platform.python_version(),
        "docker": command(["docker", "version"]),
        "compose": command(["docker", "compose", "version"]),
        "seed": None, "ml_model": "not evaluated (regex stub)",
        "anomaly_inbound": 5,
        "corpus_sha256": hashlib.sha256(corpus_path.read_bytes()).hexdigest(),
    }
    metadata["source_sha256"] = {
        path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
        for path in ("docker-compose.yml", "docker/waf-crs/Dockerfile",
                     "docker/web-app/Dockerfile", "web-app/app.py",
                     "web-app/requirements.txt", "docker/db/init/01-schema.sql",
                     "docker/db/init/02-seed.sql", "waf-crs/run_integrated_smoke.py")
    }
    (out / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    all_rows, summaries = [], []
    for level in args.levels:
        env["CRS_PL"] = str(level)
        command(COMPOSE + ["up", "-d", "--wait", "--wait-timeout", "180"], env)
        engine = command(COMPOSE + ["exec", "-T", "waf-crs", "printenv", "MODSEC_RULE_ENGINE"], env).strip()
        if engine != "On":
            raise RuntimeError("Blocking validation requires MODSEC_RULE_ENGINE=On; no baseline reported")
        waf_port = loopback_port("waf-crs", 8080, env)
        app_port = loopback_port("web-app", 5000, env)
        config = command(COMPOSE + ["exec", "-T", "waf-crs", "sh", "-c",
            "nginx -v 2>&1; cat /etc/modsecurity.d/modsecurity.conf; cat /etc/modsecurity.d/owasp-crs/crs-setup.conf"], env)
        (out / f"pl{level}-effective-config.txt").write_text(config, encoding="utf-8")
        # Record image identities, not container environments containing .env values.
        metadata["images"] = command(COMPOSE + ["images", "--format", "json"], env)
        metadata["backend_version"] = command(COMPOSE + ["exec", "-T", "web-app", "python", "-c",
            "import sys,importlib.metadata as m; from app import _db_config; import pymysql; "
            "c=pymysql.connect(**_db_config()); q=c.cursor(); q.execute('SELECT VERSION() AS version'); "
            "print(sys.version); print({p:m.version(p) for p in ['Flask','Werkzeug','PyMySQL']}); "
            "print(q.fetchone()); c.close()"], env)
        audit_offset = AUDIT.stat().st_size if AUDIT.exists() else 0
        app_offset = APP.stat().st_size if APP.exists() else 0
        rows = []
        for case in corpus:
            correlation = f"{run_id}-pl{level}-{case['id']}"
            direct = send(app_port, case["request"], correlation + "-direct")
            via_waf = send(waf_port, case["request"], correlation)
            rows.append({"case_id": case["id"], "correlation_id": correlation,
                "technique": case["technique"], "label": case["label"],
                "paranoia_level": level, "request": case["request"],
                "http_status": via_waf["status"], "latency_ms": via_waf["latency_ms"],
                "wire": {"url": via_waf["raw_url"], "body": via_waf["raw_body"]},
                "response_body": via_waf["body"], "direct_response": direct})
        deadline = time.monotonic() + 10
        while True:
            audits, apps = lines_since(AUDIT, audit_offset), lines_since(APP, app_offset)
            audit_map = {audit_id(a): a for a in audits if audit_id(a)}
            app_map = {a.get("case_id"): a for a in apps}
            complete = all(r["correlation_id"] in audit_map
                           and r["correlation_id"] + "-direct" in app_map
                           and (r["http_status"] != 200 or r["correlation_id"] in app_map)
                           for r in rows)
            if complete or time.monotonic() > deadline:
                break
            time.sleep(0.2)
        (out / f"pl{level}-audit.json").write_text(json.dumps(audits, indent=2), encoding="utf-8")
        (out / f"pl{level}-app.json").write_text(json.dumps(apps, indent=2, ensure_ascii=False), encoding="utf-8")
        (out / f"pl{level}-responses.json").write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
        if not complete:
            raise RuntimeError(f"Missing correlated evidence; incomplete run: {out}")
        for row in rows:
            cid = row["correlation_id"]
            control = app_map[cid + "-direct"]
            intended = row["label"] == "malicious"
            if (row["direct_response"]["status"] != 200 or control["sql_error"]
                    or control["semantic_effect"] != intended):
                raise RuntimeError(f"Invalid direct control {row['case_id']}; incomplete run: {out}")
            transaction = audit_map[cid]["transaction"]
            rule_ids = sorted({str(m.get("details", {}).get("ruleId", ""))
                               for m in transaction.get("messages", [])} - {""})
            app_record = app_map.get(cid)
            blocked = row["http_status"] == 403 and "949110" in rule_ids and app_record is None
            allowed = row["http_status"] == 200 and app_record is not None
            if (not (blocked or allowed)
                    or int(transaction["response"]["http_code"]) != row["http_status"]
                    or (app_record and app_record["sql_error"])):
                raise RuntimeError(f"Unclassified/error outcome {row['case_id']}; incomplete run: {out}")
            detected = any(rule.startswith("942") for rule in rule_ids)
            effect = bool(app_record and app_record["semantic_effect"])
            row.update(waf_decision="blocked" if blocked else "allowed", detected=detected,
                       reached_app=app_record is not None, semantic_effect=effect,
                       true_bypass=intended and allowed and not detected and effect,
                       rule_ids=rule_ids, app_evidence=app_record, direct_control=control)
            metadata.setdefault("runtime_producer", {})[str(level)] = transaction["producer"]
        summary = {"paranoia_level": level, **summarize(rows)}
        summaries.append(summary)
        all_rows.extend(rows)
        (out / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        (out / "results.json").write_text(json.dumps(all_rows, indent=2, ensure_ascii=False), encoding="utf-8")
        (out / "summary.json").write_text(json.dumps(summaries, indent=2), encoding="utf-8")
        print(json.dumps(summary), flush=True)
    with (out / "results.csv").open("w", newline="", encoding="utf-8") as stream:
        fields = ["case_id", "label", "paranoia_level", "http_status", "waf_decision",
                  "detected", "reached_app", "semantic_effect", "true_bypass", "rule_ids", "latency_ms"]
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_rows)
    print("Evidence: " + str(out), flush=True)


if __name__ == "__main__":
    main()
