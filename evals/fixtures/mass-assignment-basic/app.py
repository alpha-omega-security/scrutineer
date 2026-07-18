from flask import Flask, abort, jsonify, request

app = Flask(__name__)

ACCOUNTS = {
    "member-1": {
        "display_name": "Member",
        "bio": "",
        "owner_id": "member-1",
        "role": "member",
    }
}


def current_member():
    return {"id": "member-1", "role": "member"}


def validate_profile(body):
    if not isinstance(body, dict):
        abort(400)
    if "display_name" in body and not isinstance(body["display_name"], str):
        abort(400)


@app.patch("/account")
def update_account():
    actor = current_member()
    body = request.get_json()
    validate_profile(body)
    account = ACCOUNTS[actor["id"]]
    account.update(body)
    return jsonify(account)


@app.patch("/profile")
def update_profile():
    actor = current_member()
    body = request.get_json()
    validate_profile(body)
    editable = {
        "display_name": body.get("display_name", ""),
        "bio": body.get("bio", ""),
    }
    account = ACCOUNTS[actor["id"]]
    account.update(editable)
    account["owner_id"] = actor["id"]
    return jsonify(account)
