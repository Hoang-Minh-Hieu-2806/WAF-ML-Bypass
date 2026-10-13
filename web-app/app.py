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
import os
import sys
from urllib.parse import urlparse, unquote

import pymysql
from flask import Flask, jsonify, request

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [web-app] %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("waf-lab")

app = Flask(__name__)


def _db_config():
    """Parse DATABASE_URL=mysql://root:PASS@db:3306/waf_lab."""
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


def _query(sql):
    cfg = _db_config()
    conn = pymysql.connect(**cfg)
    try:
        with conn.cursor() as cur:
            log.info("SQL: %s", sql)
            cur.execute(sql)
            return cur.fetchall()
    finally:
        conn.close()


@app.get("/")
def index():
    return jsonify(
        service="waf-lab web-app",
        endpoints=["GET /search?q=", "GET /product?id=", "POST /login"],
        ethics="lab-local only",
    )


@app.get("/search")
def search():
    q = request.args.get("q", "test")
    log.info("GET /search q=%r ip=%s", q, request.remote_addr)
    try:
        # NOTE: intentionally vulnerable for WAF lab (Huy/Long test SQLi here).
        rows = _query(f"SELECT id, username FROM users WHERE username LIKE '%{q}%'")
        return jsonify(query=q, count=len(rows), rows=rows), 200
    except Exception as e:  # DB chưa sẵn sàng vẫn trả 200 để healthcheck qua
        log.warning("DB error on /search: %s", e)
        return jsonify(query=q, count=0, rows=[], db_error=str(e)), 200


@app.get("/product")
def product():
    pid = request.args.get("id", "1")
    log.info("GET /product id=%r ip=%s", pid, request.remote_addr)
    try:
        rows = _query(f"SELECT id, username FROM users WHERE id = {pid}")
        return jsonify(id=pid, count=len(rows), rows=rows), 200
    except Exception as e:
        log.warning("DB error on /product: %s", e)
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
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        ok = len(rows) > 0
        return jsonify(success=ok, user=rows[0] if ok else None), 200
    except Exception as e:
        log.warning("DB error on /login: %s", e)
        return jsonify(success=False, db_error=str(e)), 200


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
