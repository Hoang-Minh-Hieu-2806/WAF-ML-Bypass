"""T03 — Controlled target web-app (lab local only).

Owner deployment: Hoang Minh Hieu.
3 endpoint cho milestone Tuan 01-04:
  GET  /search?q=       -> SELECT ... WHERE username LIKE '%q%'
  GET  /product?id=     -> SELECT ... WHERE id = <id>
  POST /login           -> SELECT ... WHERE username='<u>' AND password='<p>'

Chu y: query co y de dang vulnerable (string interpolation) de WAF co viec lam.
Chi chay trong lab Docker noi bo, khong expose DB ra host, khong dung data that.
"""
import logging
import json
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, unquote

import pymysql
from flask import Flask, g, jsonify, request

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [web-app] %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("waf-lab")

app = Flask(__name__)
EVIDENCE_LOCK = threading.Lock()


@app.before_request
def capture_request():
    # Cache the bytes before Flask parses form/JSON bodies.
    g.raw_body = request.get_data(cache=True).decode("utf-8", errors="replace")
    g.query = None
    g.row_ids = []
    g.reference_row_ids = []
    g.semantic_effect = False
    g.sql_error = None


@app.after_request
def record_evidence(response):
    case_id = request.headers.get("X-Lab-Case-ID")
    if case_id:
        response.headers["X-Lab-Case-ID"] = case_id
    # Healthchecks do not belong to the experiment corpus.
    if request.path not in ("/search", "/product", "/login"):
        return response
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "case_id": case_id, "method": request.method,
        "raw_target": request.path + ("?" + request.query_string.decode("ascii", errors="replace")
                                      if request.query_string else ""),
        "raw_body": g.raw_body,
        "parsed_pairs": list(request.args.items(multi=True)),
        "form_pairs": list(request.form.items(multi=True)),
        "parser": "Flask/Werkzeug; first-value-wins; MySQL via PyMySQL",
        "query": g.query, "row_ids": g.row_ids,
        "reference_row_ids": g.reference_row_ids,
        "sql_error": g.sql_error, "semantic_effect": g.semantic_effect,
        "http_status": response.status_code,
    }
    log_path = Path(os.getenv("APP_LOG", "/evidence/app.jsonl"))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with EVIDENCE_LOCK, log_path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, ensure_ascii=False) + "\n")
    return response


def _db_config():
    """Use literal DB settings; retain a percent-encoded URI as legacy fallback."""
    if "DB_PASSWORD" in os.environ:
        return {
            "host": os.getenv("DB_HOST", "db"),
            "port": int(os.getenv("DB_PORT", "3306")),
            "user": os.getenv("DB_USER", "root"),
            "password": os.environ["DB_PASSWORD"],
            "database": os.getenv("DB_NAME", "waf_lab"),
            "connect_timeout": 5,
            "cursorclass": pymysql.cursors.DictCursor,
        }
    url = os.getenv("DATABASE_URL", "mysql://root:changeme_strong_pass@db:3306/waf_lab")
    u = urlparse(url)
    return {
        "host": u.hostname or "db",
        "port": u.port or 3306,
        "user": unquote(u.username or "root"),
        "password": unquote(u.password or ""),
        "database": (u.path or "/waf_lab").lstrip("/"),
        "connect_timeout": 5,
        "cursorclass": pymysql.cursors.DictCursor,
    }


def _query(sql, reference_sql, reference_params):
    """Run the vulnerable handler and a bound reference on the same DB connection.

    Extra returned identities prove predicate expansion/authentication bypass.
    Legitimate LIKE wildcards can return many rows without being an SQLi effect.
    The reference is an observation oracle; the lab handler remains vulnerable.
    """
    g.query = sql
    cfg = _db_config()
    conn = pymysql.connect(**cfg)
    try:
        with conn.cursor() as cur:
            log.info("SQL: %s", sql)
            cur.execute(sql)
            rows = cur.fetchall()
            cur.execute(reference_sql, reference_params)
            reference_rows = cur.fetchall()
            g.row_ids = [row["id"] for row in rows]
            g.reference_row_ids = [row["id"] for row in reference_rows]
            g.semantic_effect = bool(set(g.row_ids) - set(g.reference_row_ids))
            return rows
    finally:
        conn.close()


@app.get("/")
def index():
    return jsonify(
        service="waf-lab web-app",
        endpoints=["GET /search?q=", "GET /product?id=", "POST /login"],
        ethics="lab-local only",
    )


@app.get("/healthz")
def health():
    # Unlike /search's existing API, readiness must fail if the DB is unusable.
    try:
        conn = pymysql.connect(**_db_config())
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        finally:
            conn.close()
        return jsonify(status="ok"), 200
    except Exception:
        return jsonify(status="unavailable"), 503


@app.get("/search")
def search():
    q = request.args.get("q", "test")
    log.info("GET /search q=%r ip=%s", q, request.remote_addr)
    try:
        # NOTE: intentionally vulnerable for WAF lab (Huy/Long test SQLi here).
        rows = _query(f"SELECT id, username FROM users WHERE username LIKE '%{q}%'",
                      "SELECT id, username FROM users WHERE username LIKE %s", (f"%{q}%",))
        return jsonify(query=q, count=len(rows), rows=rows), 200
    except Exception as e:  # DB chưa sẵn sàng vẫn trả 200 để healthcheck qua
        log.warning("DB error on /search: %s", e)
        g.sql_error = str(e)
        return jsonify(query=q, count=0, rows=[], db_error=str(e)), 200


@app.get("/product")
def product():
    pid = request.args.get("id", "1")
    log.info("GET /product id=%r ip=%s", pid, request.remote_addr)
    try:
        rows = _query(f"SELECT id, username FROM users WHERE id = {pid}",
                      "SELECT id, username FROM users WHERE id = %s", (pid,))
        return jsonify(id=pid, count=len(rows), rows=rows), 200
    except Exception as e:
        log.warning("DB error on /product: %s", e)
        g.sql_error = str(e)
        return jsonify(id=pid, count=0, rows=[], db_error=str(e)), 200


@app.post("/login")
def login():
    data = request.get_json(silent=True) or request.form or {}
    username = data.get("username", "")
    password = data.get("password", "")
    log.info("POST /login user=%r ip=%s", username, request.remote_addr)
    try:
        rows = _query(
            f"SELECT id, username FROM users "
            f"WHERE username = '{username}' AND password = '{password}'",
            "SELECT id, username FROM users WHERE username = %s AND password = %s",
            (username, password),
        )
        ok = len(rows) > 0
        return jsonify(success=ok, user=rows[0] if ok else None), 200
    except Exception as e:
        log.warning("DB error on /login: %s", e)
        g.sql_error = str(e)
        return jsonify(success=False, db_error=str(e)), 200


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
