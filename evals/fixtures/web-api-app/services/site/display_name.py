import hmac


def update_display_name(values, headers, session, account, origin):
    """Change the signed-in account's display name from a same-origin form."""
    if headers.get("Origin") != origin:
        return 403, {}, {"error": "origin rejected"}
    if not hmac.compare_digest(values.get("csrf", [""])[0], session["csrf"]):
        return 403, {}, {"error": "token rejected"}
    account["name"] = values.get("name", [account["name"]])[0]
    return 200, {}, {"name": account["name"]}
