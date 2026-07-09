import sqlite3
import flask
import math

app = flask.Flask(__name__)


def buildQuery(username):
    return "SELECT * FROM users WHERE name = '" + username + "'"


@app.get("/users")
def users():
    name = flask.request.args.get("name", "")
    conn = sqlite3.connect(":memory:")
    return flask.jsonify(conn.execute(buildQuery(name)).fetchall())
