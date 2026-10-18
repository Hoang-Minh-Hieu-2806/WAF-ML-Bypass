"""Intentionally vulnerable synthetic SQLi fixture, for the isolated CRS lab only.

Not the team's final web-app. SQLite is reset for each request; no real data.
"""
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

LOG = Path(os.environ.get("APP_LOG", "/evidence/app.jsonl"))
LOCK = threading.Lock()


def evaluate(method, path, pairs):
    # Explicit policy: first value wins. No second URL decoding step.
    params = {}
    for key, value in pairs:
        params.setdefault(key, value)
    db = sqlite3.connect(":memory:")
    db.executescript("""
        CREATE TABLE products(id INTEGER, name TEXT);
        INSERT INTO products VALUES (1, 'laptop'), (2, 'keyboard'), (3, 'monitor');
        CREATE TABLE users(username TEXT, password TEXT);
        INSERT INTO users VALUES ('student', 'lab-only');
    """)
    query = None
    effect = False
    rows = []
    error = None
    try:
        if method == "GET" and path == "/search":
            query = "SELECT id,name FROM products WHERE name = '" + params.get("q", "") + "'"
            rows = db.execute(query).fetchall()
            effect = len(rows) == 3
        elif method == "GET" and path == "/product":
            query = "SELECT id,name FROM products WHERE id = " + params.get("id", "1")
            rows = db.execute(query).fetchall()
            effect = len(rows) == 3
        elif method == "POST" and path == "/login":
            username, password = params.get("username", ""), params.get("password", "")
            query = "SELECT username FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
            rows = db.execute(query).fetchall()
            effect = bool(rows) and (username, password) != ("student", "lab-only")
        else:
            return 404, {"error": "unknown endpoint"}
    except sqlite3.Error as exc:
        error = str(exc)
    finally:
        db.close()
    return 200, {"parser": "urllib.parse.parse_qsl; first-value-wins; decode-once",
                 "parsed_pairs": pairs, "query": query, "rows": rows,
                 "sql_error": error, "semantic_effect": effect}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def handle_request(self):
        target = urlsplit(self.path)
        if target.path == "/healthz":
            self.reply(200, {"status": "ok"})
            return
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        pairs = parse_qsl(target.query, keep_blank_values=True)
        if self.command == "POST":
            pairs += parse_qsl(body.decode("utf-8"), keep_blank_values=True)
        status, result = evaluate(self.command, target.path, pairs)
        result.update({"case_id": self.headers.get("X-Lab-Case-ID"),
                       "method": self.command, "raw_target": self.path,
                       "raw_body": body.decode("utf-8", errors="replace"),
                       "timestamp": datetime.now(timezone.utc).isoformat()})
        LOG.parent.mkdir(parents=True, exist_ok=True)
        with LOCK, LOG.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(result, ensure_ascii=False) + "\n")
        self.reply(status, result)

    def reply(self, status, value):
        data = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
