import flask

app = flask.Flask(__name__)


def validate_session(session_cookie):
    return session_cookie == "known-session"


def serve_account_data():
    return flask.jsonify({"account_number": "1234", "balance": 100})


@app.get("/account")
def account():
    session_cookie = flask.request.cookies.get("session")
    if session_cookie:
        if not validate_session(session_cookie):
            flask.abort(401)
    return serve_account_data()


@app.get("/account-safe")
def safe_account():
    session_cookie = flask.request.cookies.get("session")
    if not session_cookie:
        flask.abort(401)
    if not validate_session(session_cookie):
        flask.abort(401)
    return serve_account_data()
