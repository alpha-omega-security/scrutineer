import json
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer

USERS = {"alice": "alice-password", "bob": "bob-password"}
NOTES = {
    1: {"owner": "alice", "title": "Alice groceries"},
    2: {"owner": "bob", "title": "Bob reading list"},
}
SESSIONS = {}


def dispatch(method, path, headers, body=b""):
    if method == "POST" and path == "/login":
        try:
            creds = json.loads(body or b"{}")
        except ValueError:
            return 400, {"error": "bad request"}
        username = creds.get("username", "")
        if USERS.get(username) != creds.get("password"):
            return 403, {"error": "login failed"}
        token = secrets.token_urlsafe(32)
        SESSIONS[token] = username
        return 200, {"token": token}
    token = headers.get("Authorization", "").removeprefix("Bearer ")
    user = SESSIONS.get(token)
    if not user:
        return 401, {"error": "login required"}
    if method == "GET" and path == "/notes":
        return 200, [{"id": nid, "title": n["title"]} for nid, n in NOTES.items() if n["owner"] == user]
    if method == "GET" and path.startswith("/notes/"):
        note = NOTES.get(int(path.rsplit("/", 1)[1])) if path.rsplit("/", 1)[1].isdigit() else None
        if not note:
            return 404, {"error": "not found"}
        if note["owner"] != user:
            return 403, {"error": "forbidden"}
        return 200, {"title": note["title"]}
    return 404, {"error": "not found"}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if length < 0:
            self.send_error(400)
            return
        if length > 8192:
            self.send_error(413)
            return
        body = self.rfile.read(length) if length else b""
        status, result = dispatch(self.command, self.path, self.headers, body)
        data = json.dumps(result).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    HTTPServer(("localhost", 8080), Handler).serve_forever()
