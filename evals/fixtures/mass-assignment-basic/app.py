from flask import Flask, abort

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


from account import register_account_routes
from profile import register_profile_routes

register_account_routes(app, ACCOUNTS, current_member, validate_profile)
register_profile_routes(app, ACCOUNTS, current_member, validate_profile)
