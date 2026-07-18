import flask

app = flask.Flask(__name__)
app.secret_key = "dev"


@app.get("/profile")
def profile():
    user_id = flask.session.get("user_id")
    # No session means no principal: reject the request before any
    # authorised branch runs. The credential is required, so the
    # check fails closed on a missing value.
    if not user_id:
        return flask.jsonify({"error": "unauthorized"}), 401
    return flask.jsonify({"profile": "user-%s" % user_id})


if __name__ == "__main__":
    app.run()
