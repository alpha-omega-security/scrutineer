from flask import jsonify, request


def register_profile_routes(app, accounts, current_member, validate_profile):
    @app.patch("/profile")
    def update_profile():
        actor = current_member()
        body = request.get_json()
        validate_profile(body)
        editable = {
            "display_name": body.get("display_name", ""),
            "bio": body.get("bio", ""),
        }
        account = accounts[actor["id"]]
        account.update(editable)
        account["owner_id"] = actor["id"]
        return jsonify(account)
