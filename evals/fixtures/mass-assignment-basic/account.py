from flask import jsonify, request


def register_account_routes(app, accounts, current_member, validate_profile):
    @app.patch("/account")
    def update_account():
        actor = current_member()
        body = request.get_json()
        validate_profile(body)
        account = accounts[actor["id"]]
        account.update(body)
        return jsonify(account)
