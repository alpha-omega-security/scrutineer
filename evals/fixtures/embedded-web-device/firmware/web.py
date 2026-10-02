import hmac
import json

ADMIN_PASSWORD = "plug-admin-4821"
SETTINGS = {"name": "plug", "relay": False}


def dispatch(method, path, headers, body=""):
    if method == "GET" and path == "/status":
        return 200, {"name": SETTINGS["name"], "relay": SETTINGS["relay"]}
    if method == "POST" and path == "/admin/settings":
        supplied = headers.get("X-Admin-Password", "")
        if not hmac.compare_digest(supplied, ADMIN_PASSWORD):
            return 401, {"error": "admin password required"}
        values = json.loads(body or "{}")
        SETTINGS.update({key: values[key] for key in ("name", "relay") if key in values})
        return 200, SETTINGS
    return 404, {"error": "not found"}
