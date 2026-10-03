import hmac
import json
import secrets
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

from display_name import update_display_name


ACCOUNTS = {"demo": {"password": "demo-password", "email": "demo@example.test", "name": "Demo"}}
SESSIONS = {}
ORIGIN = "http://localhost:8080"


def dispatch(method, target, headers, body=""):
    url = urlsplit(target)
    values = parse_qs(body if method == "POST" else url.query)
    if method == "POST" and url.path == "/login":
        username = values.get("username", [""])[0]
        password = values.get("password", [""])[0]
        account = ACCOUNTS.get(username)
        if not account or not hmac.compare_digest(account["password"], password):
            return 403, {}, {"error": "login failed"}
        token = secrets.token_urlsafe(32)
        SESSIONS[token] = {"username": username, "csrf": secrets.token_urlsafe(32)}
        return 200, {"Set-Cookie": f"session={token}; HttpOnly; SameSite=Lax; Path=/"}, {"ok": True}
    cookie = SimpleCookie()
    cookie.load(headers.get("Cookie", ""))
    token = cookie["session"].value if "session" in cookie else ""
    session = SESSIONS.get(token)
    if not session:
        return 401, {}, {"error": "login required"}
    account = ACCOUNTS[session["username"]]
    if method == "GET" and url.path == "/api/account":
        return 200, {}, {"email": account["email"], "name": account["name"], "csrf": session["csrf"]}
    if method == "GET" and url.path == "/api/email":
        account["email"] = values.get("email", [account["email"]])[0]
        return 200, {}, {"email": account["email"]}
    if method == "POST" and url.path == "/api/display-name":
        return update_display_name(values, headers, session, account, ORIGIN)
    return 404, {}, {"error": "not found"}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 8192:
            self.send_error(413)
            return
        body = self.rfile.read(length).decode("utf-8") if length else ""
        status, headers, result = dispatch(self.command, self.path, self.headers, body)
        data = json.dumps(result).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    HTTPServer(("localhost", 8080), Handler).serve_forever()
