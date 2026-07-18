import flask

app = flask.Flask(__name__)

EXPECTED_KEY = "supersecret"


@app.get("/admin")
def admin():
    supplied = flask.request.headers.get("X-API-Key")
    # Only reject when a key _is_ given and differs from the expected one.
    # A request that omits the header entirely falls through to the
    # authorised branch, so the check fails open on a missing credential.
    if supplied and supplied != EXPECTED_KEY:
        return flask.jsonify({"error": "forbidden"}), 403
    return flask.jsonify({"data": "secret admin payload"})


if __name__ == "__main__":
    app.run()
